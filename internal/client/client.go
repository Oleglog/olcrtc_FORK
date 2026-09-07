// Package client implements the local SOCKS5 client side of the olcrtc tunnel.
package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/names"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/xtaci/smux"
)

var (
	// ErrConnectFailed is returned when a tunnel connection fails.
	ErrConnectFailed = errors.New("tunnel connection failed")
	// ErrProxyAuth is returned when SOCKS proxy authentication fails.
	ErrProxyAuth = errors.New("SOCKS proxy auth failed")
	// ErrKeySize is returned when the encryption key is not 32 bytes.
	// Re-exported from runtime for compatibility with errors.Is callers.
	ErrKeySize = runtime.ErrKeySize
	// ErrInvalidSOCKSVersion is returned when the SOCKS version is not 5.
	ErrInvalidSOCKSVersion = errors.New("invalid socks version")
	// ErrUnsupportedSOCKSCommand is returned for unsupported SOCKS commands.
	ErrUnsupportedSOCKSCommand = errors.New("unsupported socks command")
	// ErrUnsupportedAddressType is returned for unsupported SOCKS address types.
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	// ErrRemoteNotReady is returned when the server-side stream fails to signal readiness.
	ErrRemoteNotReady = errors.New("remote not ready")
	// ErrSOCKSAuthFailed is returned when username/password authentication is rejected.
	ErrSOCKSAuthFailed = errors.New("SOCKS5 authentication failed")
	// ErrSOCKSCredTooLong is returned when a SOCKS5 username or password exceeds 255 bytes.
	ErrSOCKSCredTooLong = errors.New("socks5 user/pass exceeds 255 bytes")
	// ErrUDPDisabled is returned for UDP ASSOCIATE when the server was built
	// without relay support (UDPEnabled=false on the mobile API).
	ErrUDPDisabled = errors.New("udp relay is disabled")
)

// SOCKS5 command codes (RFC 1928, section 4).
const (
	socksCmdConnect      = 1
	socksCmdUDPAssociate = 3
)

// SOCKS5 address types (RFC 1928, section 4.5) used by the UDP datagram
// codec below.
const (
	socksAtypIPv4   = 1
	socksAtypDomain = 3
	socksAtypIPv6   = 4
)

// udpAssociateCommand is the smux-stream handshake command the client sends
// to open a UDP relay. It must stay in lockstep with the server's
// udpAssociateCommand ("udp-associate") — there is no shared package between
// the two, only this wire string and the length-prefixed frame format.
const udpAssociateCommand = "udp-associate"

// UDP relay framing knobs. Datagrams ride one smux stream ("udp-associate")
// as length-prefixed frames; a relay read deadline resets when the app's TCP
// control connection drops so a wedged relay cannot leak a smux stream.
// Keepalive frames (zero payload) are sent during silence so the server's
// 5-minute stream deadline cannot expire mid-call.
const (
	udpRelayFrameCap     = 64 * 1024
	udpRelayReadTimeout  = 2 * time.Minute
	udpRelayWriteTimeout = 30 * time.Second
	udpKeepaliveInterval = 30 * time.Second
)

// Client handles local SOCKS5 connections and tunnels them to the server.
type Client struct {
	ln          transport.Transport
	cipher      *crypto.Cipher
	conn        *muxconn.Conn
	session     *smux.Session
	controlStrm *smux.Stream
	controlStop context.CancelFunc
	sessMu      sync.RWMutex
	reconnectMu sync.Mutex
	health      *runtime.HealthTracker
	deviceID    string
	sessionID   string
	claims      map[string]any
	dnsServer   string
	socksUser   string
	socksPass   string
	udpEnabled  bool
}

// HealthFunc is called when the client control health snapshot changes.
type HealthFunc func(control.Status)

// Config holds runtime configuration for [Run] and [RunWithReady].
type Config struct {
	Transport        string
	Carrier          string
	RoomURL          string
	ChannelID        string
	KeyHex           string
	LocalAddr        string
	DNSServer        string
	Insecure         bool
	SOCKSUser        string
	SOCKSPass        string
	// UDPEnabled gates UDP ASSOCIATE: when false, UDP ASSOCIATE requests are
	// refused with ErrUDPDisabled (SOCKS reply 0x07). Default off until the
	// relay proves itself on device; flip via the app's UDP toggle.
	UDPEnabled       bool
	TransportOptions transport.Options
	Engine           string
	URL              string
	Token            string
	AuthToken        string
	Liveness         control.Config
	Traffic          transport.TrafficConfig

	// DeviceID overrides the persistent client-side device identifier. Leave
	// empty to derive one from DeviceIDPath (or generate a random one if both
	// are empty).
	DeviceID string

	// DeviceIDPath is a file in which to persist the auto-generated device ID
	// across restarts. Ignored when DeviceID is set explicitly.
	DeviceIDPath string

	// Claims is sent to the server in CLIENT_HELLO and forwarded verbatim to
	// the server's AuthHook. Free-form key/value bag for plan, user, region, etc.
	Claims map[string]any

	// OnHealth receives liveness/reconnect status updates. Nil means no-op.
	OnHealth HealthFunc
}

// Run starts the client with the given configuration.
func Run(ctx context.Context, cfg Config) error {
	return RunWithReady(ctx, cfg, nil)
}

// RunWithReady is like Run but invokes onReady once the local SOCKS listener is up.
func RunWithReady(ctx context.Context, cfg Config, onReady func()) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cipher, err := setupCipher(cfg.KeyHex)
	if err != nil {
		return fmt.Errorf("setupCipher failed: %w", err)
	}

	deviceID, err := resolveDeviceID(cfg.DeviceID, cfg.DeviceIDPath)
	if err != nil {
		return fmt.Errorf("resolve device id: %w", err)
	}

	c := &Client{
		cipher:     cipher,
		deviceID:   deviceID,
		claims:     cfg.Claims,
		dnsServer:  cfg.DNSServer,
		socksUser:  cfg.SOCKSUser,
		socksPass:  cfg.SOCKSPass,
		udpEnabled: cfg.UDPEnabled,
		health:     runtime.NewHealthTracker(cfg.OnHealth),
	}

	// shutdown is registered BEFORE bringUpLink so we always close any
	// link/session that bringUpLink managed to set up before it
	// errored out. The previous ordering returned early on failure
	// (e.g. handshake timeout against a wedged seichannel transport)
	// without ever calling Close on the carrier link, leaving our MUC
	// presence behind as a ghost participant in the next test that
	// joined the same room. shutdown is nil-safe — it skips fields
	// that bringUpLink hadn't populated yet.
	defer c.shutdown()

	if err := c.bringUpLink(runCtx, cfg, cancel); err != nil {
		return err
	}

	lc := net.ListenConfig{}
	listener, err := lc.Listen(runCtx, "tcp4", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.LocalAddr, err)
	}
	defer func() { _ = listener.Close() }()

	logger.Infof("SOCKS5 server listening on %s", cfg.LocalAddr)

	if onReady != nil {
		onReady()
	}

	go c.acceptLoop(runCtx, listener)

	<-runCtx.Done()
	return nil
}

func (c *Client) bringUpLink(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
) error {
	ln, err := transport.New(ctx, cfg.Transport, transport.Config{
		Carrier:   cfg.Carrier,
		RoomURL:   cfg.RoomURL,
		Engine:    cfg.Engine,
		URL:       cfg.URL,
		Token:     cfg.Token,
		ChannelID: cfg.ChannelID,
		DeviceID:  c.deviceID,
		Name:      names.Generate(),
		OnData:    c.onData,
		DNSServer: cfg.DNSServer,
		Insecure:  cfg.Insecure,
		Options:   cfg.TransportOptions,
		Traffic:   cfg.Traffic,
	})
	if err != nil {
		return fmt.Errorf("failed to create link: %w", err)
	}
	c.ln = ln

	ln.SetEndedCallback(func(reason string) {
		logger.Infof("Client link reported conference end: %s", reason)
		cancel()
	})
	ln.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	ln.SetReconnectCallback(func() {
		if ctx.Err() != nil {
			return
		}
		// Carrier callback fires after the link is back up. If handshake
		// still fails it usually means the server hasn't completed its
		// own reinstall yet — keep the listener up and wait for either
		// another callback or a future liveness loss to re-trigger.
		c.handleReconnect(ctx, cfg, cancel, "carrier")
	})

	if err := ln.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect link: %w", err)
	}
	if err := waitForPeer(ctx, ln); err != nil {
		return err
	}

	c.conn = muxconn.New(ln, c.cipher)
	sess, err := smux.Client(c.conn, runtime.SmuxConfigFor(ln))
	if err != nil {
		return fmt.Errorf("smux client: %w", err)
	}

	control, sid, err := openControlStream(ctx, sess, c.deviceID, c.claims)
	if err != nil {
		_ = sess.Close()
		_ = c.conn.Close()
		return fmt.Errorf("handshake: %w", err)
	}
	logger.Infof("session %s opened (device=%s)", sid, c.deviceID)

	c.sessMu.Lock()
	c.session = sess
	c.controlStrm = control
	c.sessionID = sid
	c.sessMu.Unlock()
	c.recordSession(sid)
	c.startControlLoop(ctx, cfg, cancel, control)

	go ln.WatchConnection(ctx)
	return nil
}

// peerWaitTimeout bounds how long bringUpLink/tryReopenSession will block
// waiting for a remote peer before opening smux. This uses the same budget as
// the handshake path so a missing peer fails quickly instead of hanging before
// the SOCKS listener is ready.
const peerWaitTimeout = handshake.DefaultTimeout

func waitForPeer(ctx context.Context, ln transport.Transport) error {
	waiter, ok := ln.(transport.PeerReadyTransport)
	if !ok {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, peerWaitTimeout)
	defer cancel()
	if err := waiter.WaitForPeer(waitCtx); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	return nil
}

// openControlStream opens stream #1 on sess and performs the handshake.
// The stream stays open for the lifetime of the smux session and carries
// post-handshake control messages.
func openControlStream(
	ctx context.Context,
	sess *smux.Session,
	deviceID string,
	claims map[string]any,
) (*smux.Stream, string, error) {
	return openControlStreamTimeout(ctx, sess, deviceID, claims, handshake.DefaultTimeout)
}

func openControlStreamTimeout(
	ctx context.Context,
	sess *smux.Session,
	deviceID string,
	claims map[string]any,
	timeout time.Duration,
) (*smux.Stream, string, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, "", fmt.Errorf("open control stream: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	_ = stream.SetDeadline(time.Now().Add(timeout))
	sid, err := handshake.Client(stream, deviceID, claims)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		_ = stream.Close()
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("handshake client: %w", ctx.Err())
		}
		return nil, "", fmt.Errorf("handshake client: %w", err)
	}
	return stream, sid, nil
}

// resolveDeviceID returns the device ID to send in CLIENT_HELLO.
//
// Precedence:
//  1. Explicit deviceID arg (Config.DeviceID) — used verbatim.
//  2. Persistent file at path (Config.DeviceIDPath) — read if it exists,
//     otherwise generated and written for future runs.
//  3. Random UUID per run when both inputs are empty.
func resolveDeviceID(deviceID, path string) (string, error) {
	if deviceID != "" {
		return deviceID, nil
	}
	if path == "" {
		return uuid.NewString(), nil
	}
	// #nosec G304 -- persistent device ID path is explicit user configuration.
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read device id %s: %w", path, err)
	}
	id := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("mkdir device id dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write device id %s: %w", path, err)
	}
	return id, nil
}

func smuxConfig(maxWirePayload int) *smux.Config {
	return runtime.SmuxConfig(maxWirePayload)
}

func (c *Client) handleReconnect(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.recordReconnect()
	logger.Infof("client reconnect reason=%s - tearing down smux session", reason)
	c.resetLinkPeer()

	// Close the old muxconn immediately so any in-flight Push from data
	// arriving on the new bridge is discarded. Without this, the server
	// side that reconnected faster can push frames into our old muxconn,
	// corrupting the dying smux session.
	c.sessMu.RLock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.sessMu.RUnlock()

	// Install a fresh muxconn immediately so onData never hits nil while
	// the old session is being torn down. tryReopenSession will swap it
	// again with its own conn on each attempt.
	newConn := muxconn.New(c.ln, c.cipher)

	c.sessMu.Lock()
	oldControl := c.controlStrm
	oldControlStop := c.controlStop
	oldSess := c.session
	c.conn = newConn
	c.session = nil
	c.controlStrm = nil
	c.controlStop = nil
	c.sessionID = ""
	c.sessMu.Unlock()

	if oldControlStop != nil {
		oldControlStop()
	}
	if oldSess != nil {
		_ = oldSess.Close()
	}
	if oldControl != nil {
		_ = oldControl.Close()
	}

	// When liveness on top of a still-"connected" carrier expires, the
	// underlying ICE/data path has gone silent without the engine noticing.
	// Re-handshaking over the dead carrier just times out repeatedly, so
	// ask the carrier to rebuild itself; the new carrier will fire its own
	// reconnect callback which then drives a fresh handshake.
	if reason == "liveness" && c.ln != nil {
		c.ln.Reconnect("liveness")
		// Return immediately — retryHandshake over the dead link would
		// loop forever with "open control stream: timeout" while holding
		// reconnectMu, blocking the carrier callback that fires once the
		// link is actually back up. Let that callback (reason="carrier")
		// drive the handshake when the transport is ready.
		return
	}

	c.retryHandshake(ctx, cfg, cancel, reason)
}

func (c *Client) retryHandshake(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	const (
		initialDelay = 300 * time.Millisecond
		maxDelay     = 5 * time.Second
	)
	delay := initialDelay
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		logger.Infof("client reconnect attempt=%d reason=%s", attempt, reason)
		if c.tryReopenSession(ctx, cfg, cancel, attempt) {
			return
		}
		// Don't fail the whole process on liveness reconnect: the carrier
		// rebuild may take dozens of seconds (e.g. ICE restart on a flaky
		// network). Keep the SOCKS5 listener open and wait — handleSocks5
		// will return host-unreachable to clients until we recover. For
		// carrier-driven reconnects the callback fires after the link is
		// already up, so a missed handshake is more suspicious; cap it.
		if reason == "carrier" && attempt >= 5 {
			logger.Warnf("client reconnect: exhausted %d handshake attempts (reason=%s) — keeping listener up", attempt, reason)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (c *Client) resetLinkPeer() {
	c.sessMu.RLock()
	ln := c.ln
	c.sessMu.RUnlock()
	if resetter, ok := ln.(interface{ ResetPeer() }); ok {
		resetter.ResetPeer()
	}
}

func (c *Client) tryReopenSession(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
	attempt int,
) bool {
	if err := waitForPeer(ctx, c.ln); err != nil {
		logger.Warnf("wait for peer on reconnect failed (attempt %d): %v", attempt, err)
		return false
	}
	conn := muxconn.New(c.ln, c.cipher)

	c.sessMu.Lock()
	old := c.conn
	c.conn = conn
	c.sessMu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	sess, err := smux.Client(conn, runtime.SmuxConfigFor(c.ln))
	if err != nil {
		logger.Warnf("smux re-init failed (attempt %d): %v", attempt, err)
		return false
	}
	control, sid, err := openControlStreamTimeout(ctx, sess, c.deviceID, c.claims, 2*time.Second)
	if err != nil {
		logger.Warnf("handshake on reconnect failed (attempt %d): %v", attempt, err)
		_ = sess.Close()
		return false
	}
	logger.Infof("session %s reopened (device=%s)", sid, c.deviceID)
	c.sessMu.Lock()
	c.session = sess
	c.controlStrm = control
	c.sessionID = sid
	c.sessMu.Unlock()
	c.recordSession(sid)
	c.startControlLoop(ctx, cfg, cancel, control)
	return true
}

func (c *Client) startControlLoop(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
	stream *smux.Stream,
) {
	controlCtx, stop := context.WithCancel(ctx)
	c.sessMu.Lock()
	c.controlStop = stop
	c.sessMu.Unlock()

	liveness := cfg.Liveness
	// Control-plane carriers (vp8channel) can legitimately stall control pongs
	// under KCP batching / SFU renegotiation; relax the pong timeout so a busy
	// link is not declared dead. Conventional carriers keep the conservative
	// default (issue #95).
	if runtime.IsControlPlane(c.ln) && liveness.Timeout <= control.DefaultTimeout {
		liveness.Timeout = runtime.LivenessTimeout(c.ln)
	}
	onPong := liveness.OnPong
	onMissedPong := liveness.OnMissedPong
	onUnhealthy := liveness.OnUnhealthy
	liveness.OnPong = func(h control.Health) {
		c.sessMu.RLock()
		sid := c.sessionID
		c.sessMu.RUnlock()
		c.recordPong(h)
		logger.Debugf("control alive session=%s rtt=%v seq=%d", sid, h.RTT, h.Seq)
		if onPong != nil {
			onPong(h)
		}
	}
	liveness.OnMissedPong = func(missed int) {
		c.recordMissed(missed)
		logger.Warnf("control missed pong on client: missed_pongs=%d", missed)
		if onMissedPong != nil {
			onMissedPong(missed)
		}
	}
	liveness.OnUnhealthy = func(missed int) {
		c.recordUnhealthy(missed)
		logger.Warnf("control stream unhealthy on client: missed_pongs=%d", missed)
		if onUnhealthy != nil {
			onUnhealthy(missed)
		}
	}

	go func() {
		err := control.Run(controlCtx, stream, liveness)
		if controlCtx.Err() != nil || ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Warnf("client control stream ended: %v", err)
		}
		// handleReconnect now retries indefinitely on liveness so it only
		// returns false on ctx cancellation; don't tear down the client.
		c.handleReconnect(ctx, cfg, cancel, "liveness")
	}()
}

// Status returns the latest client-side control health snapshot.
func (c *Client) Status() control.Status {
	return c.health.Status()
}

func (c *Client) recordSession(sessionID string) { c.health.RecordSession(sessionID) }
func (c *Client) recordPong(h control.Health)    { c.health.RecordPong(h) }
func (c *Client) recordMissed(missed int)        { c.health.RecordMissed(missed) }
func (c *Client) recordUnhealthy(missed int)     { c.health.RecordUnhealthy(missed) }
func (c *Client) recordReconnect()               { c.health.RecordReconnect() }

func (c *Client) shutdown() {
	c.sessMu.Lock()
	control := c.controlStrm
	controlStop := c.controlStop
	sess := c.session
	conn := c.conn
	c.controlStrm = nil
	c.controlStop = nil
	c.session = nil
	c.conn = nil
	c.sessMu.Unlock()

	notifyControlClose(control)
	if controlStop != nil {
		controlStop()
	}
	if sess != nil {
		_ = sess.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if control != nil {
		_ = control.Close()
	}
}

func notifyControlClose(stream *smux.Stream) {
	if stream == nil {
		return
	}
	_ = stream.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := control.SendClose(stream); err == nil {
		time.Sleep(200 * time.Millisecond)
	}
	_ = stream.SetWriteDeadline(time.Time{})
	_ = stream.CloseWrite()
}

func setupCipher(keyHex string) (*crypto.Cipher, error) {
	cipher, err := runtime.SetupCipher(keyHex)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	return cipher, nil
}

func (c *Client) onData(data []byte) {
	c.sessMu.RLock()
	conn := c.conn
	c.sessMu.RUnlock()
	if conn != nil {
		conn.Push(data)
	}
}

func (c *Client) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warnf("Accept error: %v", err)
				continue
			}
		}
		go c.handleSocks5(ctx, conn)
	}
}

func (c *Client) handleSocks5(_ context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := c.socks5Handshake(conn); err != nil {
		return
	}

	targetAddr, targetPort, udpAssociate, err := c.socks5Request(conn)
	if err != nil {
		return
	}

	c.sessMu.RLock()
	sess := c.session
	c.sessMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		_, _ = conn.Write(replyHostUnreachable())
		return
	}

	if udpAssociate {
		c.serveUDPAssociate(conn, sess)
		return
	}
	c.tunnel(conn, sess, targetAddr, targetPort)
}

func (c *Client) tunnel(conn net.Conn, sess *smux.Session, targetAddr string, targetPort int) {
	stream, err := sess.OpenStream()
	if err != nil {
		logger.Warnf("OpenStream failed: %v", err)
		_, _ = conn.Write(replyHostUnreachable())
		return
	}
	defer func() { _ = stream.Close() }()

	logger.Infof("sid=%d tunnel to %s:%d", stream.ID(), targetAddr, targetPort)

	if err := c.sendConnectRequest(stream, targetAddr, targetPort); err != nil {
		logger.Warnf("sid=%d connect failed: %v", stream.ID(), err)
		_, _ = conn.Write(replyHostUnreachable())
		return
	}

	if _, err := conn.Write(replySuccess()); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(stream, conn)
		_ = stream.Close()
	}()
	_, _ = io.Copy(conn, stream)
}

// connectRequest is the JSON command frame opening one smux data stream.
// It mirrors server.ConnectRequest; both sides must stay in lockstep
// because the field names are the wire protocol.
type connectRequest struct {
	Cmd  string `json:"cmd"`
	Addr string `json:"addr,omitempty"`
	Port int    `json:"port,omitempty"`
}

func (c *Client) sendConnectRequest(stream *smux.Stream, targetAddr string, targetPort int) error {
	connectReq, err := json.Marshal(connectRequest{
		Cmd:  "connect",
		Addr: targetAddr,
		Port: targetPort,
	})
	if err != nil {
		return fmt.Errorf("sid=%d marshal connect req: %w", stream.ID(), err)
	}

	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write(connectReq); err != nil {
		return fmt.Errorf("sid=%d write connect req: %w", stream.ID(), err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	ack := make([]byte, 1)
	_ = stream.SetReadDeadline(time.Now().Add(runtime.ConnectAckTimeout(c.ln)))
	if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0x00 {
		return fmt.Errorf("sid=%d: %w (read_err=%w ack=%v)", stream.ID(), ErrRemoteNotReady, err, ack)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return nil
}

func (c *Client) socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read socks5 header: %w", err)
	}
	if buf[0] != 5 {
		return fmt.Errorf("%w: %d", ErrInvalidSOCKSVersion, buf[0])
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read socks5 methods: %w", err)
	}

	if c.socksUser != "" {
		// RFC 1929: method 0x02 = username/password auth.
		if _, err := conn.Write([]byte{5, 2}); err != nil {
			return fmt.Errorf("write socks5 auth method: %w", err)
		}
		if err := c.socks5UserPassAuth(conn); err != nil {
			return err
		}
		return nil
	}

	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return fmt.Errorf("write socks5 auth: %w", err)
	}
	return nil
}

// serveUDPAssociate implements RFC 1928 UDP ASSOCIATE over the tunnel: it
// opens one smux stream ("udp-associate"), binds a loopback UDP socket, and
// shuttles datagrams between the app and the server. The app's TCP control
// connection stays open for the relay lifetime; when it drops, the UDP
// socket closes and the smux stream is released.
func (c *Client) serveUDPAssociate(tcpConn net.Conn, sess *smux.Session) {
	if !c.udpEnabled {
		_, _ = tcpConn.Write(replyCommandNotSupported())
		return
	}
	stream, err := sess.OpenStream()
	if err != nil {
		logger.Warnf("udp-associate OpenStream failed: %v", err)
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	if err := sendUDPAssociateRequest(stream); err != nil {
		logger.Warnf("udp-associate handshake failed: %v", err)
		_ = stream.Close()
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		logger.Warnf("udp-associate listen failed: %v", err)
		_ = stream.Close()
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	relayAddr := pc.LocalAddr()
	logger.Infof("udp-associate relay on %s", relayAddr)
	if _, err := tcpConn.Write(socksAssociateReply(relayAddr)); err != nil {
		_ = pc.Close()
		_ = stream.Close()
		return
	}
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	// Xray's socks outbound uses one UDP socket per UDP session, so the
	// first app datagram latches the peer; every response is addressed back
	// to it (RFC 1928 keeps the destination inside each datagram instead).
	// writeMu serializes frame writes across the pumps and the keepalive:
	// smux splits large Writes into multiple wire frames, so interleaved
	// writers would corrupt the framing.
	peerCh := make(chan *net.UDPAddr, 1)
	writeMu := &sync.Mutex{}
	writeFrame := func(addr string, port int, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = stream.SetWriteDeadline(time.Now().Add(udpRelayWriteTimeout))
		return writeUDPRelayFrame(stream, addr, port, payload)
	}
	go func() {
		buf := make([]byte, 1)
		_, _ = tcpConn.Read(buf)
		finish()
	}()
	go udpPacketsToStream(pc, stream, done, peerCh, writeFrame)
	go func() {
		select {
		case <-done:
			return
		case peer := <-peerCh:
			udpStreamToPackets(stream, pc, peer, finish)
		}
	}()
	// Zero-payload frames keep the server's stream deadline from expiring
	// while the app is silent (muted call, idle QUIC session).
	keepaliveStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(udpKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-keepaliveStop:
				return
			case <-ticker.C:
				if err := writeFrame("", 0, nil); err != nil {
					finish()
					return
				}
			}
		}
	}()
	defer close(keepaliveStop)
	<-done
	_ = pc.Close()
	_ = stream.Close()
}

// sendUDPAssociateRequest opens the relay handshake on a fresh smux stream:
// one JSON frame {cmd:"udp-associate"} then a 1-byte ack (0x00 = ready).
func sendUDPAssociateRequest(stream *smux.Stream) error {
	req, err := json.Marshal(connectRequest{Cmd: udpAssociateCommand})
	if err != nil {
		return fmt.Errorf("marshal udp-associate req: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write(req); err != nil {
		return fmt.Errorf("write udp-associate req: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})
	ack := make([]byte, 1)
	_ = stream.SetReadDeadline(time.Now().Add(runtime.ConnectAckTimeout(nil)))
	if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0x00 {
		return fmt.Errorf("%w (read_err=%v ack=%v)", ErrRemoteNotReady, err, ack)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return nil
}

// udpStreamToPackets decodes length-prefixed frames from the smux stream and
// sends each as one UDP datagram back to the app-side peer. Response frames
// from the server are wrapped in a SOCKS5 UDP header (encodeSocksUDPDatagram)
// because the peer is Xray's socks outbound, which expects every datagram it
// reads to carry the RFC 1928 [RSV RSV FRAG][addr][port] prefix.
func udpStreamToPackets(stream *smux.Stream, pc net.PacketConn, peer *net.UDPAddr, onDone func()) {
	defer onDone()
	for {
		_ = stream.SetReadDeadline(time.Now().Add(udpRelayReadTimeout))
		addr, port, payload, err := readUDPRelayFrame(stream)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			// Zero-payload frames are server keepalives; they reset the read
			// deadline but must not reach the app as datagrams.
			continue
		}
		datagram := encodeSocksUDPDatagram(addr, port, payload)
		_ = pc.SetWriteDeadline(time.Now().Add(udpRelayWriteTimeout))
		if _, err := pc.WriteTo(datagram, peer); err != nil {
			return
		}
	}
}

// udpPacketsToStream decodes each inbound datagram's SOCKS5 UDP header
// (decodeSocksUDPDatagram) to recover the real destination, then ships the
// payload as a relay frame. Xray's socks outbound writes every datagram as
// [RSV RSV FRAG][ATYP][addr][port][data]; the destination lives inside the
// datagram, not in the packet's source address. The first datagram also
// latches the app-side peer so responses can be addressed back to it.
func udpPacketsToStream(
	pc net.PacketConn,
	stream *smux.Stream,
	done <-chan struct{},
	peerCh chan<- *net.UDPAddr,
	writeFrame func(addr string, port int, payload []byte) error,
) {
	buf := make([]byte, udpRelayFrameCap)
	sentPeer := false
	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpRelayReadTimeout))
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		udpAddr, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		if !sentPeer {
			sentPeer = true
			select {
			case peerCh <- udpAddr:
			default:
			}
		}
		addr, port, payload, err := decodeSocksUDPDatagram(buf[:n])
		if err != nil {
			logger.Debugf("udp-associate datagram decode failed: %v", err)
			continue
		}
		if err := writeFrame(addr, port, payload); err != nil {
			return
		}
	}
}

// encodeSocksUDPDatagram wraps one relay payload in the RFC 1928 UDP header
// with the remote address, mirroring the format Xray's socks UDPReader
// decodes. IPv4 and IPv6 use ATYP 1/4, hostnames are never emitted because
// relay frames carry resolved IPs only.
func encodeSocksUDPDatagram(addr string, port int, payload []byte) []byte {
	out := make([]byte, 0, 3+net.IPv4len+2+len(payload)+2)
	out = append(out, 0, 0, 0) // RSV RSV FRAG=0 (no fragmentation)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port)) //nolint:gosec // G115: port range fits u16
	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, socksAtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, socksAtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		// Unparseable relay address: fall back to a zero IPv4 header so the
		// datagram stays decodable; Xray will drop it as a bad destination.
		out = append(out, socksAtypIPv4, 0, 0, 0, 0)
	}
	out = append(out, portBuf[:]...)
	return append(out, payload...)
}

// decodeSocksUDPDatagram parses the RFC 1928 UDP header from one app-side
// datagram, returning the destination address, port and payload. Fragmented
// datagrams (FRAG != 0) are rejected: nothing in the stack fragments and
// reassembly is out of scope for the relay.
func decodeSocksUDPDatagram(datagram []byte) (string, int, []byte, error) {
	if len(datagram) < 4 {
		return "", 0, nil, ErrUnsupportedAddressType
	}
	if datagram[2] != 0 {
		return "", 0, nil, fmt.Errorf("fragmented udp datagram (frag=%d)", datagram[2])
	}
	off := 3
	var addr string
	switch atyp := datagram[off]; atyp {
	case socksAtypIPv4:
		if len(datagram) < off+1+net.IPv4len+2 {
			return "", 0, nil, ErrUnsupportedAddressType
		}
		addr = net.IP(datagram[off+1 : off+1+net.IPv4len]).String()
		off += 1 + net.IPv4len
	case socksAtypDomain:
		if len(datagram) < off+2 {
			return "", 0, nil, ErrUnsupportedAddressType
		}
		nameLen := int(datagram[off+1])
		if len(datagram) < off+2+nameLen+2 {
			return "", 0, nil, ErrUnsupportedAddressType
		}
		addr = string(datagram[off+2 : off+2+nameLen])
		off += 2 + nameLen
	case socksAtypIPv6:
		if len(datagram) < off+1+net.IPv6len+2 {
			return "", 0, nil, ErrUnsupportedAddressType
		}
		addr = net.IP(datagram[off+1 : off+1+net.IPv6len]).String()
		off += 1 + net.IPv6len
	default:
		return "", 0, nil, fmt.Errorf("%w: atyp=%d", ErrUnsupportedAddressType, atyp)
	}
	if len(datagram) < off+2 {
		return "", 0, nil, ErrUnsupportedAddressType
	}
	port := int(binary.BigEndian.Uint16(datagram[off : off+2])) //nolint:gosec // G115: port range fits u16
	return addr, port, datagram[off+2:], nil
}

// writeUDPRelayFrame encodes one datagram: [u16 addrLen][addr][u16 port][payload].
func writeUDPRelayFrame(w io.Writer, addr string, port int, payload []byte) error {
	frame := make([]byte, 0, 4+len(addr)+len(payload))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(addr))) //nolint:gosec // G115: loopback datagrams, bounded by frame cap
	frame = append(frame, lenBuf[:]...)
	frame = append(frame, []byte(addr)...)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(port)) //nolint:gosec // G115: port range fits u16
	frame = append(frame, lenBuf[:]...)
	frame = append(frame, payload...)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame))) //nolint:gosec // G115: bounded by construction
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

// readUDPRelayFrame decodes one frame written by writeUDPRelayFrame.
func readUDPRelayFrame(r io.Reader) (string, int, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 0, nil, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size < 4 || size > udpRelayFrameCap {
		return "", 0, nil, fmt.Errorf("bad udp relay frame size %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", 0, nil, err
	}
	if len(body) < 4 {
		return "", 0, nil, fmt.Errorf("truncated udp relay frame")
	}
	addrLen := int(binary.BigEndian.Uint16(body[:2]))
	if 2+addrLen+2 > len(body) {
		return "", 0, nil, fmt.Errorf("truncated udp relay address")
	}
	addr := string(body[2 : 2+addrLen])
	port := int(binary.BigEndian.Uint16(body[2+addrLen : 2+addrLen+2]))
	return addr, port, body[2+addrLen+2:], nil
}

func (c *Client) socks5UserPassAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks5 auth header: %w", err)
	}
	if header[0] != 0x01 {
		return fmt.Errorf("%w: expected auth version 1, got %d", ErrInvalidSOCKSVersion, header[0])
	}
	ulen := int(header[1])
	userBuf := make([]byte, ulen)
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return fmt.Errorf("read socks5 username: %w", err)
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("read socks5 plen: %w", err)
	}

	plen := int(plenBuf[0])
	passBuf := make([]byte, plen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return fmt.Errorf("read socks5 password: %w", err)
	}

	if string(userBuf) != c.socksUser || string(passBuf) != c.socksPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return ErrSOCKSAuthFailed
	}

	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("write socks5 auth success: %w", err)
	}

	return nil
}

func (c *Client) socks5Request(conn net.Conn) (string, int, bool, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, false, fmt.Errorf("read socks5 request: %w", err)
	}
	if header[1] != socksCmdConnect && header[1] != socksCmdUDPAssociate {
		return "", 0, false, fmt.Errorf("%w: %d", ErrUnsupportedSOCKSCommand, header[1])
	}

	addr, err := c.readSocks5Addr(conn, header[3])
	if err != nil {
		return "", 0, false, err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, false, fmt.Errorf("read socks5 port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return addr, port, header[1] == socksCmdUDPAssociate, nil
}

func (c *Client) readSocks5Addr(conn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case 1: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read socks5 ipv4: %w", err)
		}
		return net.IP(buf).String(), nil
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read socks5 domain len: %w", err)
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read socks5 domain: %w", err)
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("%w: %d", ErrUnsupportedAddressType, addrType)
	}
}

// socksAssociateReply builds the UDP ASSOCIATE success reply advertising the
// loopback relay endpoint (BND.ADDR/BND.PORT per RFC 1928 section 4).
func socksAssociateReply(relay net.Addr) []byte {
	host, port := "127.0.0.1", 0
	if udp, ok := relay.(*net.UDPAddr); ok {
		if ip := udp.IP; ip != nil && ip.To4() != nil {
			host = ip.String()
		}
		port = udp.Port
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1).To4()
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port)) //nolint:gosec // G115: port range fits u16
	reply := []byte{5, 0, 0, 1}
	reply = append(reply, ip...)
	return append(reply, portBuf[:]...)
}

func replySuccess() []byte {
	return []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
}

func replyHostUnreachable() []byte {
	return []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}
}

// replyCommandNotSupported answers 0x07 (command not supported) for gated
// requests such as UDP ASSOCIATE with the relay disabled.
func replyCommandNotSupported() []byte {
	return []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}
}
