// Package mobile provides a gomobile-compatible API for olcRTC.
// Build with: gomobile bind -target=android ./mobile
package mobile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"

	"github.com/openlibrecommunity/olcrtc/internal/transport/vp8channel"

	_ "golang.org/x/mobile/bind"                       // ensure gomobile bind is available
	_ "google.golang.org/genproto/protobuf/field_mask" // keep gomobile on post-split genproto modules
)

// SocketProtector protects sockets from VPN routing on Android.
// Implement this interface in Kotlin/Java and pass to SetProtector.
type SocketProtector interface {
	Protect(fd int) bool
}

// LogWriter receives log messages from olcRTC.
type LogWriter interface {
	WriteLog(msg string)
}

var (
	errAlreadyRunning       = errors.New("olcRTC already running")
	errCarrierRequired      = errors.New("carrier is required")
	errRoomIDRequired       = errors.New("roomID is required")
	errClientIDRequired     = errors.New("clientID is required")
	errKeyHexRequired       = errors.New("keyHex is required")
	errTransportRequired      = errors.New("transport is required")
	errUnsupportedTransport   = errors.New("unsupported transport: want vp8channel or datachannel")
	errIncompatibleCombo      = errors.New("incompatible carrier and transport")
	errNotRunning           = errors.New("olcRTC is not running")
	errStoppedBeforeReady   = errors.New("olcRTC stopped before becoming ready")
	errStartTimedOut        = errors.New("olcRTC start timed out")
	errHTTPPingTimedOut     = errors.New("HTTP ping timed out")
	errUnexpectedHTTPStatus = errors.New("unexpected HTTP status")
)

const (
	defaultTransport   = "vp8channel"
	dataTransport      = "datachannel"
	defaultDNSServer   = "8.8.8.8:53"
	defaultHTTPPingURL = "https://www.google.com/generate_204"
	carrierWBStream    = "wbstream"
)

const (
	httpPingWarmupTimeout = 1500 * time.Millisecond
	httpPingSampleTimeout = 1500 * time.Millisecond
	httpPingSamples       = 3
	httpPingSampleDelay   = 80 * time.Millisecond
)

var (
	mu                 sync.Mutex            //nolint:gochecknoglobals // package-level state intentional
	defaults           mobileConfig          //nolint:gochecknoglobals // package-level state intentional
	defaultsSet        sync.Once             //nolint:gochecknoglobals // package-level state intentional
	registerSet        sync.Once             //nolint:gochecknoglobals // package-level state intentional
	runClientWithReady = client.RunWithReady //nolint:gochecknoglobals // package-level state intentional
	cancel             context.CancelFunc    //nolint:gochecknoglobals // package-level state intentional
	done               chan struct{}         //nolint:gochecknoglobals // package-level state intentional
	ready              chan struct{}         //nolint:gochecknoglobals // package-level state intentional
	errRun             error
)

type mobileConfig struct {
	transport        string
	dnsServer        string
	authToken        string
	vp8FPS           int
	vp8BatchSize     int
	livenessInterval time.Duration
	livenessTimeout  time.Duration
	livenessFailures int
	udpEnabled       bool
}

// SetProtector sets the Android VPN socket protector.
// Must be called before Start.
func SetProtector(p SocketProtector) {
	if p == nil {
		protect.Protector = nil
		return
	}
	protect.Protector = func(fd int) bool {
		return p.Protect(fd)
	}
}

// SetLogWriter sets a custom log writer for olcRTC output.
func SetLogWriter(w LogWriter) {
	if w != nil {
		log.SetOutput(&logBridge{w: w})
	}
}

// SetProviders registers built-in carriers, links, and transports.
func SetProviders() {
	registerDefaults()
}

// SetTransport selects the transport used by Start.
// Supported values: vp8channel and datachannel. Unknown names are rejected
// instead of silently falling back, so a typo cannot start the wrong stack.
func SetTransport(transport string) error {
	normalized := normalizeTransport(transport)
	if normalized == "" {
		return errUnsupportedTransport
	}
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.transport = normalized
	return nil
}

// SetDNS selects the DNS server used by the tunnel.
func SetDNS(dnsServer string) {
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.dnsServer = dnsServer
}

// SetWBToken sets the pre-issued wbstream account token (auth.token).
// When set, the session joins as that account instead of an anonymous guest;
// empty keeps the guest flow. It is especially useful for wbstream datachannel
// rooms that require an account/moderator token with publish permissions.
func SetWBToken(token string) {
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.authToken = strings.TrimSpace(token)
}

// SetVP8Options configures vp8channel.
func SetVP8Options(fps, batchSize int) {
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.vp8FPS = clampAtLeastOne(fps, 120)
	defaults.vp8BatchSize = clampAtLeastOne(batchSize, 64)
}

// SetUDPEnabled toggles the UDP ASSOCIATE relay for Start/Check/Ping.
// Default off: UDP ASSOCIATE requests are refused (SOCKS 0x07) until the
// app flips this on after the relay proves itself on device.
func SetUDPEnabled(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.udpEnabled = enabled
}

// SetLivenessOptions configures control-stream ping/pong checks.
// Values <= 0 reset that field to its default. Durations are milliseconds.
func SetLivenessOptions(intervalMillis, timeoutMillis, failures int) {
	mu.Lock()
	defer mu.Unlock()
	ensureDefaultConfigLocked()
	defaults.livenessInterval = durationFromMillisOrDefault(intervalMillis, control.DefaultInterval)
	defaults.livenessTimeout = durationFromMillisOrDefault(timeoutMillis, control.DefaultTimeout)
	if failures <= 0 {
		defaults.livenessFailures = control.DefaultFailures
		return
	}
	defaults.livenessFailures = failures
}

// SetDebug enables or disables verbose logging.
func SetDebug(enabled bool) {
	logger.SetVerbose(enabled)
	if enabled {
		log.SetFlags(log.Ltime | log.Lshortfile)
		return
	}

	log.SetFlags(log.Ltime)
}

// Start launches the olcRTC client in background.
// carrierName: carrier name ("telemost", "wbstream", "jitsi")
// roomID: carrier-specific room ID
// clientID: client identifier that must match the server's -client-id
// keyHex: 64-char hex encryption key
// socksPort: local SOCKS5 proxy port (e.g. 10808)
// socksUser/socksPass: SOCKS5 credentials (empty = no auth).
func Start(carrierName, roomID, clientID, keyHex string, socksPort int, socksUser, socksPass string) error {
	mu.Lock()
	ensureDefaultConfigLocked()
	cfg := defaults
	mu.Unlock()

	return startWithConfig(carrierName, cfg.transport, roomID, clientID, keyHex, socksPort, socksUser, socksPass, cfg)
}

// StartWithTransport launches the client with an explicit transport for this start.
func StartWithTransport(
	carrierName, transportName, roomID, clientID, keyHex string,
	socksPort int,
	socksUser, socksPass string,
) error {
	mu.Lock()
	ensureDefaultConfigLocked()
	cfg := defaults
	cfg.transport = transportName
	mu.Unlock()

	return startWithConfig(carrierName, transportName, roomID, clientID, keyHex, socksPort, socksUser, socksPass, cfg)
}

// Check starts an isolated short-lived client and returns elapsed milliseconds once ready.
// It does not use the singleton Start/Stop runtime, so callers may run checks in parallel.
func Check(
	carrierName, transportName, roomID, clientID, keyHex string,
	socksPort int,
	timeoutMillis int,
	vp8FPS int,
	vp8BatchSize int,
) (int64, error) {
	registerDefaults()
	mu.Lock()
	ensureDefaultConfigLocked()
	cfg := defaults
	mu.Unlock()

	carrierName = normalizeCarrier(carrierName)
	transportName = normalizeTransport(transportName)
	if transportName == "" {
		return 0, errUnsupportedTransport
	}
	if err := validateStartArgs(carrierName, roomID, clientID, keyHex); err != nil {
		return 0, err
	}
	if err := validateCarrierTransport(carrierName, transportName); err != nil {
		return 0, err
	}

	if timeoutMillis <= 0 {
		timeoutMillis = 8000
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	readyCh := make(chan struct{})
	doneCh := make(chan error, 1)
	var readyOnce sync.Once
	startedAt := time.Now()

	go func() {
		doneCh <- runClientWithReady(
			ctx,
			client.Config{
				Transport: transportName,
				Carrier:   carrierName,
				RoomURL:   buildRoomURL(carrierName, roomID),
				KeyHex:    keyHex,
				DeviceID:  clientID,
				LocalAddr: fmt.Sprintf("127.0.0.1:%d", socksPort),
				DNSServer: defaultDNSServer,
				AuthToken: cfg.authToken,
				UDPEnabled:  cfg.udpEnabled,
				TransportOptions: vp8channel.Options{
					FPS:       clampAtLeastOne(vp8FPS, 120),
					BatchSize: clampAtLeastOne(vp8BatchSize, 64),
				},
				Liveness: livenessConfig(cfg),
			},
			func() {
				readyOnce.Do(func() {
					close(readyCh)
				})
			},
		)
	}()

	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()

	select {
	case <-readyCh:
		elapsed := time.Since(startedAt).Milliseconds()
		cancelFunc()
		waitForCheckDone(doneCh)
		return elapsed, nil
	case err := <-doneCh:
		if err != nil {
			return 0, err
		}
		return 0, errStoppedBeforeReady
	case <-timer.C:
		cancelFunc()
		waitForCheckDone(doneCh)
		return 0, errStartTimedOut
	}
}

// Ping starts an isolated short-lived client, waits until its SOCKS listener is ready,
// performs HTTP requests through that SOCKS tunnel, and returns HTTP latency in milliseconds.
//
// The returned value does not include RTC startup time. It measures only HTTP request latency
// after the tunnel is ready.
func Ping(
	carrierName, transportName, roomID, clientID, keyHex string,
	socksPort int,
	timeoutMillis int,
	pingURL string,
	vp8FPS int,
	vp8BatchSize int,
) (int64, error) {
	registerDefaults()
	mu.Lock()
	ensureDefaultConfigLocked()
	cfg := defaults
	mu.Unlock()

	carrierName = normalizeCarrier(carrierName)
	transportName = normalizeTransport(transportName)
	if transportName == "" {
		return 0, errUnsupportedTransport
	}

	if err := validateStartArgs(carrierName, roomID, clientID, keyHex); err != nil {
		return 0, err
	}
	if err := validateCarrierTransport(carrierName, transportName); err != nil {
		return 0, err
	}

	if timeoutMillis <= 0 {
		timeoutMillis = 10000
	}
	if pingURL == "" {
		pingURL = defaultHTTPPingURL
	}

	ctx, cancelFunc := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutMillis)*time.Millisecond,
	)
	defer cancelFunc()

	readyCh := make(chan struct{})
	doneCh := make(chan error, 1)

	var readyOnce sync.Once

	go func() {
		doneCh <- runClientWithReady(
			ctx,
			client.Config{
				Transport: transportName,
				Carrier:   carrierName,
				RoomURL:   buildRoomURL(carrierName, roomID),
				KeyHex:    keyHex,
				DeviceID:  clientID,
				LocalAddr: fmt.Sprintf("127.0.0.1:%d", socksPort),
				DNSServer: defaultDNSServer,
				AuthToken: cfg.authToken,
				UDPEnabled:  cfg.udpEnabled,
				TransportOptions: vp8channel.Options{
					FPS:       clampAtLeastOne(vp8FPS, 120),
					BatchSize: clampAtLeastOne(vp8BatchSize, 64),
				},
				Liveness: livenessConfig(cfg),
			},
			func() {
				readyOnce.Do(func() {
					close(readyCh)
				})
			},
		)
	}()

	select {
	case <-readyCh:
		elapsed, err := httpPingThroughSocks(
			ctx,
			fmt.Sprintf("127.0.0.1:%d", socksPort),
			pingURL,
		)

		cancelFunc()
		waitForCheckDone(doneCh)

		if err != nil {
			return 0, err
		}

		return elapsed, nil

	case err := <-doneCh:
		if err != nil {
			return 0, err
		}

		return 0, errStoppedBeforeReady

	case <-ctx.Done():
		cancelFunc()
		waitForCheckDone(doneCh)

		return 0, errStartTimedOut
	}
}

func httpPingThroughSocks(
	parentCtx context.Context,
	socksAddr string,
	targetURL string,
) (int64, error) {
	normalizedURL, err := normalizeHTTPPingURL(targetURL)
	if err != nil {
		return 0, err
	}

	client, closeClient := newHTTPPingClient(socksAddr)
	defer closeClient()

	// Warm up the SOCKS/TCP/TLS path. This request is intentionally not included
	// in the returned latency.
	_, _ = singleHTTPPingRequest(
		parentCtx,
		client,
		normalizedURL,
		httpPingWarmupTimeout,
	)

	return bestHTTPPingSample(parentCtx, client, normalizedURL)
}

func normalizeHTTPPingURL(targetURL string) (string, error) {
	if targetURL == "" {
		targetURL = defaultHTTPPingURL
	}

	if _, err := url.ParseRequestURI(targetURL); err != nil {
		return "", fmt.Errorf("parse HTTP ping URL: %w", err)
	}

	return targetURL, nil
}

func newHTTPPingClient(socksAddr string) (*http.Client, func()) {
	proxyURL := &url.URL{
		Scheme: "socks5",
		Host:   socksAddr,
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),

		DisableKeepAlives:   false,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     10 * time.Second,

		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   httpPingSampleTimeout,
		ResponseHeaderTimeout: httpPingSampleTimeout,
		ExpectContinueTimeout: 500 * time.Millisecond,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   httpPingSampleTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, transport.CloseIdleConnections
}

func bestHTTPPingSample(
	parentCtx context.Context,
	client *http.Client,
	targetURL string,
) (int64, error) {
	var best int64
	var lastErr error

	for i := range httpPingSamples {
		elapsed, err := singleHTTPPingRequest(
			parentCtx,
			client,
			targetURL,
			httpPingSampleTimeout,
		)
		if err != nil {
			lastErr = err
		} else {
			best = bestPositiveLatency(best, elapsed)
		}

		if i < httpPingSamples-1 {
			time.Sleep(httpPingSampleDelay)
		}
	}

	if best > 0 {
		return best, nil
	}

	if lastErr != nil {
		return 0, lastErr
	}

	return 0, errHTTPPingTimedOut
}

func bestPositiveLatency(currentBest, next int64) int64 {
	if next <= 0 {
		return currentBest
	}

	if currentBest == 0 || next < currentBest {
		return next
	}

	return currentBest
}

func singleHTTPPingRequest(
	parentCtx context.Context,
	client *http.Client,
	targetURL string,
	timeout time.Duration,
) (int64, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create HTTP ping request: %w", err)
	}

	req.Header.Set("User-Agent", "Olcbox-Android")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")

	startedAt := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("perform HTTP ping request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	elapsed := time.Since(startedAt).Milliseconds()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPermanentRedirect {
		return 0, fmt.Errorf("%w: %d", errUnexpectedHTTPStatus, resp.StatusCode)
	}

	return elapsed, nil
}

func startWithConfig(
	carrierName, transportName, roomID, clientID, keyHex string,
	socksPort int,
	socksUser, socksPass string,
	cfg mobileConfig,
) error {
	mu.Lock()
	defer mu.Unlock()

	registerDefaults()
	carrierName = normalizeCarrier(carrierName)
	if cancel != nil {
		return errAlreadyRunning
	}
	if transportName != "" {
		transportName = normalizeTransport(transportName)
		if transportName == "" {
			return errUnsupportedTransport
		}
		cfg.transport = transportName
	}
	if cfg.transport == "" {
		return errTransportRequired
	}

	if err := validateStartArgs(carrierName, roomID, clientID, keyHex); err != nil {
		return err
	}
	if err := validateCarrierTransport(carrierName, cfg.transport); err != nil {
		return err
	}

	roomURL := buildRoomURL(carrierName, roomID)

	ctx, cancelFunc := context.WithCancel(context.Background())
	cancel = cancelFunc
	done = make(chan struct{})
	ready = make(chan struct{})
	localReady := ready
	errRun = nil

	var readyOnce sync.Once
	go func() {
		defer cancelFunc()

		err := runClientWithReady(
			ctx,
			client.Config{
				Transport: cfg.transport,
				Carrier:   carrierName,
				RoomURL:   roomURL,
				KeyHex:    keyHex,
				DeviceID:  clientID,
				LocalAddr: fmt.Sprintf("127.0.0.1:%d", socksPort),
				DNSServer: cfg.dnsServer,
				AuthToken: cfg.authToken,
				UDPEnabled:  cfg.udpEnabled,
				SOCKSUser: socksUser,
				SOCKSPass: socksPass,
				TransportOptions: vp8channel.Options{
					FPS:       cfg.vp8FPS,
					BatchSize: cfg.vp8BatchSize,
				},
				Liveness: livenessConfig(cfg),
			},
			func() {
				readyOnce.Do(func() {
					close(localReady)
				})
			},
		)

		mu.Lock()
		cancel = nil
		errRun = err
		mu.Unlock()
		close(done)
	}()

	return nil
}

// WaitReady blocks until the selected transport is connected and the local SOCKS5 listener is ready.
//
//nolint:cyclop // straightforward state-machine waits with multiple terminal conditions
func WaitReady(timeoutMillis int) error {
	mu.Lock()
	r := ready
	d := done
	runErr := errRun
	running := cancel != nil
	mu.Unlock()

	if r == nil {
		if runErr != nil {
			return runErr
		}

		return errNotRunning
	}

	select {
	case <-r:
		return nil
	default:
	}

	if !running {
		if runErr != nil {
			return runErr
		}

		return errStoppedBeforeReady
	}

	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()

	select {
	case <-r:
		return nil
	case <-d:
		mu.Lock()
		runErr = errRun
		mu.Unlock()
		if runErr != nil {
			return runErr
		}

		return errStoppedBeforeReady
	case <-timer.C:
		return errStartTimedOut
	}
}

// Stop gracefully stops the olcRTC client.
func Stop() {
	mu.Lock()
	cancelFunc := cancel
	doneCh := done
	mu.Unlock()

	if cancelFunc == nil {
		return
	}

	cancelFunc()

	if doneCh != nil {
		<-doneCh
	}
}

// IsRunning returns true if the olcRTC client is active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return cancel != nil
}

func registerDefaults() {
	registerSet.Do(session.RegisterDefaults)
}

func waitForCheckDone(doneCh <-chan error) {
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
	}
}

func ensureDefaultConfigLocked() {
	defaultsSet.Do(func() {
		defaults = mobileConfig{
			transport:        defaultTransport,
			dnsServer:        defaultDNSServer,
			vp8FPS:           60,
			vp8BatchSize:     8,
			livenessInterval: control.DefaultInterval,
			livenessTimeout:  control.DefaultTimeout,
			livenessFailures: control.DefaultFailures,
		}
	})
}

func livenessConfig(cfg mobileConfig) control.Config {
	interval := cfg.livenessInterval
	if interval <= 0 {
		interval = control.DefaultInterval
	}
	timeout := cfg.livenessTimeout
	if timeout <= 0 {
		timeout = control.DefaultTimeout
	}
	failures := cfg.livenessFailures
	if failures <= 0 {
		failures = control.DefaultFailures
	}
	return control.Config{
		Interval: interval,
		Timeout:  timeout,
		Failures: failures,
	}
}

func normalizeTransport(value string) string {
	// Issue #52: unknown names used to silently become vp8channel, hiding a
	// misconfiguration that then fails as an incompatible carrier combo.
	// Keep the legacy aliases, but surface anything else as an explicit
	// error at the call site instead of guessing.
	switch value {
	case dataTransport, "data", "dc":
		return dataTransport
	case defaultTransport, "vp8":
		return defaultTransport
	default:
		return ""
	}
}

func normalizeCarrier(carrierName string) string {
	if carrierName == carrierWBStream {
		return carrierWBStream
	}
	return carrierName
}

func validateStartArgs(carrierName, roomID, clientID, keyHex string) error {
	switch {
	case carrierName == "":
		return errCarrierRequired
	case roomID == "":
		return errRoomIDRequired
	case clientID == "":
		return errClientIDRequired
	case keyHex == "":
		return errKeyHexRequired
	default:
		return nil
	}
}

// validateCarrierTransport enforces the issue #52 product matrix:
// telemost/wbstream work only over vp8channel, jitsi only over datachannel.
// seichannel/videochannel are dead on this project and rejected everywhere.
func validateCarrierTransport(carrierName, transportName string) error {
	switch carrierName {
	case "telemost", carrierWBStream:
		if transportName != defaultTransport {
			return fmt.Errorf("%w: %s+%s", errIncompatibleCombo, carrierName, transportName)
		}
	case "jitsi":
		if transportName != dataTransport {
			return fmt.Errorf("%w: %s+%s", errIncompatibleCombo, carrierName, transportName)
		}
	default:
		return fmt.Errorf("%w: unknown carrier %q", errIncompatibleCombo, carrierName)
	}
	return nil
}

func buildRoomURL(_ string, roomID string) string {
	// Keep the same RoomURL value the CLI/YAML path passes into transports.
	// Auth providers may expand it for service HTTP calls, but transports
	// such as vp8channel derive peer binding from the raw room value.
	return roomID
}

func clampAtLeastOne(value, maxValue int) int {
	if value < 1 {
		return 1
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func durationFromMillisOrDefault(value int, def time.Duration) time.Duration {
	if value <= 0 {
		return def
	}
	d := time.Duration(value) * time.Millisecond
	if d <= 0 {
		return def
	}
	return d
}

// logBridge adapts LogWriter to io.Writer.
type logBridge struct {
	w LogWriter
}

func (b *logBridge) Write(p []byte) (int, error) {
	b.w.WriteLog(string(p))
	return len(p), nil
}
