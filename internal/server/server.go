// Package server implements the olcrtc tunnel server logic.
package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/framing"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/names"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/xtaci/smux"
)

const connectCommand = "connect"

// udpAssociateCommand opens a UDP relay stream: datagrams ride smux as
// length-prefixed frames (see client.writeUDPRelayFrame), one frame per
// datagram, until either side closes the stream.
const udpAssociateCommand = "udp-associate"

var (
	// ErrKeyRequired re-exports runtime.ErrKeyRequired for compatibility with
	// pre-runtime callers that errors.Is-checked it.
	ErrKeyRequired = runtime.ErrKeyRequired
	// ErrKeySize re-exports runtime.ErrKeySize for the same reason.
	ErrKeySize = runtime.ErrKeySize
	// ErrSocks5AuthFailed is returned when SOCKS5 authentication fails.
	ErrSocks5AuthFailed = errors.New("SOCKS5 auth failed")
	// ErrSocks5ConnectFailed is returned when SOCKS5 connection fails.
	ErrSocks5ConnectFailed = errors.New("SOCKS5 connect failed")
)

// SessionOpenFunc is called after a successful handshake, before the server
// accepts tunnel streams on that session.
type SessionOpenFunc func(sessionID, deviceID string, claims map[string]any)

// SessionCloseFunc is called when a session is torn down. Possible reasons:
// "reconnect" (carrier dropped and was reestablished), "closed" (graceful
// shutdown or ctx cancel).
type SessionCloseFunc func(sessionID, reason string)

// TrafficFunc is called once per tunnel stream, after the copy loops finish.
// bytesIn counts client→target bytes; bytesOut counts target→client bytes.
type TrafficFunc func(sessionID, addr string, bytesIn, bytesOut uint64)

// HealthFunc is called when the server control health snapshot changes.
type HealthFunc func(control.Status)

// PeerStatus is the privacy-safe live usage snapshot for one server instance.
type PeerStatus struct {
	ActivePeers       int
	OldestConnectedAt time.Time
}

// PeerStatusFunc is called when the live peer count changes.
type PeerStatusFunc func(PeerStatus)

// Server handles incoming tunnel connections and proxies their traffic.
type Server struct {
	ln             transport.Transport
	peerLn         transport.PeerTransport
	cipher         *crypto.Cipher
	conn           *muxconn.Conn
	session        *smux.Session
	controlStrm    *smux.Stream
	controlStop    context.CancelFunc
	sessMu         sync.RWMutex
	peerSessions   map[string]*peerSession
	peerOpenMu     sync.Mutex
	peersMu        sync.Mutex
	peerStatusMu   sync.Mutex
	peerStats      map[string]peerStat
	reinstallMu    sync.Mutex
	wg             sync.WaitGroup
	authHook       handshake.AuthFunc
	onOpen         SessionOpenFunc
	onClose        SessionCloseFunc
	onTraffic      TrafficFunc
	onPeerStatus   PeerStatusFunc
	deviceID       string
	sessionID      string
	dnsServer      string
	resolver       *net.Resolver
	socksProxyAddr string
	socksProxyPort int
	socksProxyUser string
	socksProxyPass string
	warpProxyAddr  string
	warpProxyPort  int
	liveness       control.Config
	health         *runtime.HealthTracker
	done           chan struct{}
	doneOnce       sync.Once
}

// peerStat holds the per-session info needed to report the live peer count
// and a disconnect summary.
type peerStat struct {
	deviceID string
	openedAt time.Time
}

type peerSession struct {
	peerID      string
	conn        *muxconn.Conn
	session     *smux.Session
	controlStrm *smux.Stream
	controlStop context.CancelFunc
	sessionID   string
	deviceID    string
}

// ConnectRequest is a message from the client to establish a new connection.
type ConnectRequest struct {
	Cmd  string `json:"cmd"`
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

// Config holds runtime configuration for [Run].
type Config struct {
	Transport        string
	Carrier          string
	RoomURL          string
	ChannelID        string
	KeyHex           string
	DNSServer        string
	SOCKSProxyAddr   string
	SOCKSProxyPort   int
	SOCKSProxyUser   string
	SOCKSProxyPass   string
	// WarpProxyAddr/Port point to a local SOCKS5 proxy used for client tunnel
	// traffic (the dial() path). When set it takes precedence over SOCKSProxy*
	// for that traffic so the VPS public IP is not exposed.
	WarpProxyAddr    string
	WarpProxyPort    int
	Insecure         bool
	TransportOptions transport.Options
	Engine           string
	URL              string
	Token            string
	Liveness         control.Config
	Traffic          transport.TrafficConfig

	// AuthHook is invoked after CLIENT_HELLO to authorize the client and
	// return a session ID. If nil, every client is admitted with a random UUID.
	AuthHook handshake.AuthFunc

	// OnSessionOpen fires after a successful handshake. Nil means no-op.
	OnSessionOpen SessionOpenFunc
	// OnSessionClose fires when the session is torn down (reconnect, closed). Nil means no-op.
	OnSessionClose SessionCloseFunc
	// OnTraffic fires once per tunnel stream after both copy loops finish. Nil means no-op.
	OnTraffic TrafficFunc
	// OnHealth fires when liveness/reconnect status changes. Nil means no-op.
	OnHealth HealthFunc
	// OnPeerStatus fires after link startup and whenever a peer opens or closes.
	OnPeerStatus PeerStatusFunc
}

// Run starts the server with the given configuration.
func Run(ctx context.Context, cfg Config) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cipher, err := setupCipher(cfg.KeyHex)
	if err != nil {
		return fmt.Errorf("setupCipher failed: %w", err)
	}

	hook := cfg.AuthHook
	if hook == nil {
		hook = defaultAuthHook
	}
	onOpen := cfg.OnSessionOpen
	if onOpen == nil {
		onOpen = func(string, string, map[string]any) {}
	}
	onClose := cfg.OnSessionClose
	if onClose == nil {
		onClose = func(string, string) {}
	}
	onTraffic := cfg.OnTraffic
	if onTraffic == nil {
		onTraffic = func(string, string, uint64, uint64) {}
	}
	onPeerStatus := cfg.OnPeerStatus
	if onPeerStatus == nil {
		onPeerStatus = func(PeerStatus) {}
	}
	s := &Server{
		cipher:         cipher,
		authHook:       hook,
		onOpen:         onOpen,
		onClose:        onClose,
		onTraffic:      onTraffic,
		onPeerStatus:   onPeerStatus,
		dnsServer:      cfg.DNSServer,
		socksProxyAddr: cfg.SOCKSProxyAddr,
		socksProxyPort: cfg.SOCKSProxyPort,
		socksProxyUser: cfg.SOCKSProxyUser,
		socksProxyPass: cfg.SOCKSProxyPass,
		warpProxyAddr:  cfg.WarpProxyAddr,
		warpProxyPort:  cfg.WarpProxyPort,
		liveness:       cfg.Liveness,
		health:         runtime.NewHealthTracker(cfg.OnHealth),
		peerSessions:   make(map[string]*peerSession),
		peerStats:      make(map[string]peerStat),
		done:           make(chan struct{}),
	}
	s.setupResolver()

	// Register shutdown BEFORE bringUpLink so a partial setup (e.g.
	// link.New succeeded but ln.Connect timed out) still tears the
	// link down and sends MUC presence-unavailable. Without this, an
	// early bringUpLink error returns straight to the caller and the
	// already-joined MUC presence stays behind as a ghost participant
	// for subsequent tests against the same room. shutdown is
	// idempotent and safe to call before s.serve runs.
	defer func() {
		s.shutdown()
		s.wg.Wait()
	}()

	if err := s.bringUpLink(runCtx, cfg, cancel); err != nil {
		return err
	}

	go func() {
		<-runCtx.Done()
		s.closeSession()
	}()

	s.serve(runCtx)

	return nil
}

func setupCipher(keyHex string) (*crypto.Cipher, error) {
	cipher, err := runtime.SetupCipher(keyHex)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	return cipher, nil
}

func (s *Server) setupResolver() {
	s.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, s.dnsServer)
		},
	}
}

func smuxConfig(maxWirePayload int) *smux.Config {
	return runtime.SmuxConfig(maxWirePayload)
}

// dataSmuxConfig returns the data-plane smux config for the server's transport,
// mirroring the client. Control-plane transports (vp8channel) get the relaxed
// keep-alive window so a legitimately silent carrier (publisher-PC reconnect /
// SFU renegotiation) is not torn down at the conservative 30s timeout. Keeping
// this in lockstep with the client avoids the asymmetric teardown where the
// server drops its peer data session first, surfacing as "closed pipe" on the
// client and a reconnect storm (issue #95).
func dataSmuxConfig(tr transport.Transport) *smux.Config {
	return runtime.SmuxConfigFor(tr)
}

func (s *Server) bringUpLink(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
) error {
	ln, err := transport.New(ctx, cfg.Transport, transport.Config{
		Carrier:    cfg.Carrier,
		RoomURL:    cfg.RoomURL,
		Engine:     cfg.Engine,
		URL:        cfg.URL,
		Token:      cfg.Token,
		ChannelID:  cfg.ChannelID,
		DeviceID:   "",
		Name:       names.Generate(),
		OnData:     s.onData,
		OnPeerData: s.onPeerData,
		DNSServer:  s.dnsServer,
		ProxyAddr:  s.socksProxyAddr,
		ProxyPort:  s.socksProxyPort,
		Insecure:   cfg.Insecure,
		Options:    cfg.TransportOptions,
		Traffic:    cfg.Traffic,
	})
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	s.ln = ln
	if peerLn, ok := ln.(transport.PeerTransport); ok && peerLn.SupportsPeerRouting() {
		s.peerLn = peerLn
	}

	ln.SetEndedCallback(func(reason string) {
		logger.Infof("Server link reported conference end: %s", reason)
		cancel()
	})
	ln.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	ln.SetReconnectCallback(func() {
		if ctx.Err() != nil {
			return
		}
		s.handleReconnect()
	})

	logger.Infof("Connecting transport=%s carrier=%s ...", cfg.Transport, cfg.Carrier)
	if s.peerLn == nil {
		s.installSession()
	}

	if err := ln.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect link: %w", err)
	}
	logger.Infof("Link connected")
	s.logPeersLine()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ln.WatchConnection(ctx)
	}()
	return nil
}

func (s *Server) installSession() {
	conn := muxconn.New(s.ln, s.cipher)
	sess, err := smux.Server(conn, dataSmuxConfig(s.ln))
	if err != nil {
		logger.Warnf("smux server init failed: %v", err)
		return
	}
	s.sessMu.Lock()
	s.conn = conn
	s.session = sess
	s.sessMu.Unlock()
}

func (s *Server) handleReconnect() {
	s.recordReconnect()
	logger.Infof("server reconnect reason=carrier - tearing down smux session")
	s.sessMu.RLock()
	current := s.session
	s.sessMu.RUnlock()
	s.reinstallSession(current)
}

func (s *Server) reinstallSession(dead *smux.Session) {
	s.reinstallMu.Lock()
	defer s.reinstallMu.Unlock()

	// Close the old muxconn immediately so that any in-flight Push calls
	// (from data arriving on a new bridge before this reinstall completes)
	// are discarded rather than feeding stale frames into the dying smux
	// session. Without this, a client that reconnects faster than the
	// server can push new-session smux frames into the old muxconn,
	// corrupting the old smux session's stream state (manifests as
	// "frame too large" on the control stream).
	s.sessMu.RLock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.sessMu.RUnlock()

	// Pre-build the replacement so we can swap atomically below.
	newConn := muxconn.New(s.ln, s.cipher)
	newSess, err := smux.Server(newConn, dataSmuxConfig(s.ln))
	if err != nil {
		logger.Warnf("smux server init failed: %v", err)
		_ = newConn.Close()
		return
	}

	s.sessMu.Lock()
	if s.session != dead {
		// Someone else already reinstalled — discard our build.
		s.sessMu.Unlock()
		_ = newSess.Close()
		_ = newConn.Close()
		return
	}
	oldSess := s.session
	oldControl := s.controlStrm
	oldControlStop := s.controlStop
	oldSID := s.sessionID
	s.session = newSess
	s.conn = newConn
	s.controlStrm = nil
	s.controlStop = nil
	s.sessionID = ""
	s.deviceID = ""
	s.sessMu.Unlock()

	if oldControlStop != nil {
		oldControlStop()
	}
	if oldSess != nil {
		_ = oldSess.Close()
	}
	if oldControl != nil {
		_ = oldControl.Close()
	}
	if oldSID != "" {
		s.onClose(oldSID, "reconnect")
		s.trackPeerClose(oldSID, "reconnect")
	}
}

func (s *Server) closeSession() {
	s.sessMu.Lock()
	sess := s.session
	conn := s.conn
	control := s.controlStrm
	controlStop := s.controlStop
	peers := s.peerSessions
	s.peerSessions = make(map[string]*peerSession)
	s.session = nil
	s.conn = nil
	s.controlStrm = nil
	s.controlStop = nil
	oldSID := s.sessionID
	s.sessionID = ""
	s.deviceID = ""
	s.sessMu.Unlock()

	if controlStop != nil {
		controlStop()
	}
	notifyControlClose(control)
	if sess != nil {
		_ = sess.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if oldSID != "" {
		s.onClose(oldSID, "closed")
		s.trackPeerClose(oldSID, "closed")
	}
	for _, ps := range peers {
		s.closePeerSession(ps, "closed")
	}
}

func (s *Server) removePeerSession(peerID, reason string) {
	s.sessMu.Lock()
	ps := s.peerSessions[peerID]
	if ps != nil {
		delete(s.peerSessions, peerID)
		s.dropTransportPeer(peerID)
	}
	s.sessMu.Unlock()
	if ps != nil {
		s.closePeerSession(ps, reason)
	}
}

func (s *Server) replacePeerSessionForDevice(ps *peerSession, deviceID, sessionID string) bool {
	var replaced []*peerSession
	s.sessMu.Lock()
	if s.peerSessions[ps.peerID] != ps {
		s.sessMu.Unlock()
		return false
	}
	ps.deviceID = deviceID
	ps.sessionID = sessionID
	for peerID, current := range s.peerSessions {
		if current != ps && current.deviceID == deviceID {
			delete(s.peerSessions, peerID)
			s.dropTransportPeer(peerID)
			replaced = append(replaced, current)
		}
	}
	s.sessMu.Unlock()
	for _, current := range replaced {
		s.closePeerSession(current, "reconnect")
	}
	return true
}

func (s *Server) dropTransportPeer(peerID string) {
	if dropper, ok := s.peerLn.(interface{ DropPeer(string) }); ok {
		dropper.DropPeer(peerID)
	}
}

func (s *Server) closePeerSession(ps *peerSession, reason string) {
	if ps.controlStop != nil {
		ps.controlStop()
	}
	notifyControlClose(ps.controlStrm)
	if ps.session != nil {
		_ = ps.session.Close()
	}
	if ps.conn != nil {
		_ = ps.conn.Close()
	}
	if ps.controlStrm != nil {
		_ = ps.controlStrm.Close()
	}
	if ps.sessionID != "" {
		s.onClose(ps.sessionID, reason)
		s.trackPeerClose(ps.sessionID, reason)
	}
}

// trackPeerOpen records a newly opened session and logs the live peer summary.
func (s *Server) trackPeerOpen(sessionID, deviceID string) {
	s.peerStatusMu.Lock()
	s.peersMu.Lock()
	s.peerStats[sessionID] = peerStat{deviceID: deviceID, openedAt: time.Now()}
	line := s.peersLineLocked()
	status := s.peerStatusLocked()
	s.peersMu.Unlock()
	s.publishPeerStatus(status)
	s.peerStatusMu.Unlock()
	logger.Infof("peer connected: device=%s session=%s", deviceID, sessionID)
	logger.Infof("%s", line)
}

// trackPeerClose drops a closed session and logs a disconnect summary plus the
// live peer summary.
func (s *Server) trackPeerClose(sessionID, reason string) {
	s.peerStatusMu.Lock()
	s.peersMu.Lock()
	st, ok := s.peerStats[sessionID]
	if !ok {
		s.peersMu.Unlock()
		s.peerStatusMu.Unlock()
		return // session was never tracked (or already removed) - avoid double count
	}
	delete(s.peerStats, sessionID)
	line := s.peersLineLocked()
	status := s.peerStatusLocked()
	s.peersMu.Unlock()
	s.publishPeerStatus(status)
	s.peerStatusMu.Unlock()
	logger.Infof("peer disconnected: device=%s session=%s reason=%s duration=%s",
		st.deviceID, sessionID, reason, time.Since(st.openedAt).Round(time.Second))
	logger.Infof("%s", line)
}

// peersLineLocked builds the "Current peers count: N, Devices: [...]" summary
// line from the live sessions. The caller must hold peersMu.
func (s *Server) peersLineLocked() string {
	devices := make([]string, 0, len(s.peerStats))
	for _, st := range s.peerStats {
		devices = append(devices, st.deviceID)
	}
	sort.Strings(devices)
	return fmt.Sprintf("Current peers count: %d, Devices: [%s]", len(s.peerStats), strings.Join(devices, ", "))
}

func (s *Server) peerStatusLocked() PeerStatus {
	status := PeerStatus{ActivePeers: len(s.peerStats)}
	for _, peer := range s.peerStats {
		if status.OldestConnectedAt.IsZero() || peer.openedAt.Before(status.OldestConnectedAt) {
			status.OldestConnectedAt = peer.openedAt
		}
	}
	return status
}

func (s *Server) publishPeerStatus(status PeerStatus) {
	if s.onPeerStatus != nil {
		s.onPeerStatus(status)
	}
}

// logPeersLine logs the current peer summary line (count + device list).
func (s *Server) logPeersLine() {
	s.peerStatusMu.Lock()
	s.peersMu.Lock()
	line := s.peersLineLocked()
	status := s.peerStatusLocked()
	s.peersMu.Unlock()
	s.publishPeerStatus(status)
	s.peerStatusMu.Unlock()
	logger.Infof("%s", line)
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

func (s *Server) onData(data []byte) {
	s.sessMu.RLock()
	conn := s.conn
	s.sessMu.RUnlock()
	if conn != nil {
		conn.Push(data)
	}
}

func (s *Server) onPeerData(peerID string, data []byte) {
	ps := s.getPeerSession(peerID)
	if ps == nil {
		return
	}
	ps.conn.Push(data)
}

func (s *Server) getPeerSession(peerID string) *peerSession {
	if peerID == "" || s.peerLn == nil {
		return nil
	}
	s.sessMu.Lock()
	if ps := s.peerSessions[peerID]; ps != nil {
		s.sessMu.Unlock()
		return ps
	}
	conn := muxconn.NewPeer(s.peerLn, s.cipher, peerID)
	sess, err := smux.Server(conn, dataSmuxConfig(s.ln))
	if err != nil {
		s.sessMu.Unlock()
		logger.Warnf("smux server init failed for peer %s: %v", peerID, err)
		_ = conn.Close()
		return nil
	}
	ps := &peerSession{peerID: peerID, conn: conn, session: sess}
	s.peerSessions[peerID] = ps
	s.sessMu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.servePeer(ps)
	}()
	return ps
}

// serve drives the smux Accept loop. The first accepted stream on a given
// smux session is the control stream — the handshake runs there. Subsequent
// streams are tunnel streams and proxy traffic.
func (s *Server) serve(ctx context.Context) {
	if s.peerLn != nil {
		<-ctx.Done()
		return
	}
	s.serveSingle(ctx)
}

func (s *Server) serveSingle(ctx context.Context) {
	for {
		if contextDone(ctx) {
			return
		}

		s.sessMu.RLock()
		sess := s.session
		s.sessMu.RUnlock()
		if sess == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		if !s.handshakeReady() {
			if !s.acceptHandshake(ctx, sess) {
				continue
			}
		}

		stream, err := sess.AcceptStream()
		if err != nil {
			if contextDone(ctx) {
				return
			}
			hadSession := s.handshakeReady()
			logger.Debugf("AcceptStream returned %v - reinstalling session", err)
			s.reinstallSession(sess)
			if hadSession && s.ln != nil {
				s.ln.Reconnect("liveness")
			}
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleStream(ctx, stream, s.currentSessionID())
		}()
	}
}

func (s *Server) currentSessionID() string {
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	return s.sessionID
}

func contextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// handshakeReady reports whether the current session has completed its
// handshake. The session is reset on reconnect, so this is recomputed.
func (s *Server) handshakeReady() bool {
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	return s.sessionID != ""
}

func (s *Server) acceptHandshake(ctx context.Context, sess *smux.Session) bool {
	// Retry loop: after a session reinstall, stale control frames from the
	// old client smux session may arrive on the new smux session with a
	// matching stream ID. These raw JSON bytes (e.g. CONTROL_PING) are
	// interpreted by the framing layer as an impossibly large length prefix,
	// triggering ErrFrameTooLarge. We close the polluted stream and accept
	// the next one (the real handshake).
	const maxStaleRetries = 3
	for retry := 0; retry <= maxStaleRetries; retry++ {
		stream, err := sess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
				return false
			default:
			}
			logger.Debugf("AcceptStream(control) returned %v - reinstalling session", err)
			s.resetLinkPeer()
			s.reinstallSession(sess)
			return false
		}
		_ = stream.SetDeadline(time.Now().Add(handshake.DefaultTimeout))
		hello, sid, err := handshake.Server(stream, s.authHook)
		_ = stream.SetDeadline(time.Time{})
		if err != nil {
			_ = stream.Close()
			if errors.Is(err, framing.ErrFrameTooLarge) && retry < maxStaleRetries {
				logger.Debugf("handshake: discarding stale stream (attempt %d): %v", retry+1, err)
				continue
			}
			logger.Warnf("handshake failed: %v", err)
			s.resetLinkPeer()
			s.reinstallSession(sess)
			return false
		}
		s.sessMu.Lock()
		s.deviceID = hello.DeviceID
		s.sessionID = sid
		s.sessMu.Unlock()
		s.recordSession(sid)
		s.onOpen(sid, hello.DeviceID, hello.Claims)
		s.trackPeerOpen(sid, hello.DeviceID)
		logger.Infof("session %s opened (device=%s)", sid, hello.DeviceID)
		s.startControlLoop(ctx, sess, stream)
		return true
	}
	return false
}

func (s *Server) servePeer(ps *peerSession) {
	if !s.acceptPeerHandshake(ps) {
		s.removePeerSession(ps.peerID, "closed")
		return
	}
	for {
		if s.stopping() {
			return
		}
		stream, err := ps.session.AcceptStream()
		if err != nil {
			if s.stopping() {
				return
			}
			logger.Debugf("AcceptStream(peer=%s) returned %v - closing peer session", ps.peerID, err)
			s.removePeerSession(ps.peerID, "closed")
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleStream(context.Background(), stream, ps.sessionID)
		}()
	}
}

func (s *Server) acceptPeerHandshake(ps *peerSession) bool {
	const maxStaleRetries = 3
	for retry := 0; retry <= maxStaleRetries; retry++ {
		stream, err := ps.session.AcceptStream()
		if err != nil {
			if !s.stopping() {
				logger.Debugf("AcceptStream(control peer=%s) returned %v", ps.peerID, err)
			}
			return false
		}
		_ = stream.SetDeadline(time.Now().Add(handshake.DefaultTimeout))
		hello, sid, err := handshake.Server(stream, s.authHook)
		_ = stream.SetDeadline(time.Time{})
		if err != nil {
			_ = stream.Close()
			if errors.Is(err, framing.ErrFrameTooLarge) && retry < maxStaleRetries {
				logger.Debugf("handshake failed peer=%s: discarding stale stream (attempt %d): %v", ps.peerID, retry+1, err)
				continue
			}
			logger.Warnf("handshake failed peer=%s: %v", ps.peerID, err)
			return false
		}
		ps.controlStrm = stream
		// ponytail: one global activation lock; shard by device only if handshake throughput matters.
		s.peerOpenMu.Lock()
		if !s.replacePeerSessionForDevice(ps, hello.DeviceID, sid) {
			s.peerOpenMu.Unlock()
			_ = stream.Close()
			return false
		}
		s.recordSession(sid)
		s.onOpen(sid, hello.DeviceID, hello.Claims)
		s.trackPeerOpen(sid, hello.DeviceID)
		logger.Infof("session %s opened (device=%s peer=%s)", sid, hello.DeviceID, ps.peerID)
		s.startPeerControlLoop(ps, stream)
		s.peerOpenMu.Unlock()
		return true
	}
	return false
}

func (s *Server) resetLinkPeer() {
	s.sessMu.RLock()
	ln := s.ln
	s.sessMu.RUnlock()
	if resetter, ok := ln.(interface{ ResetPeer() }); ok {
		resetter.ResetPeer()
	}
}

func (s *Server) startControlLoop(ctx context.Context, sess *smux.Session, stream *smux.Stream) {
	controlCtx, stop := context.WithCancel(ctx)
	s.sessMu.Lock()
	s.controlStrm = stream
	s.controlStop = stop
	s.sessMu.Unlock()

	liveness := s.liveness
	// Control-plane carriers (vp8channel) can legitimately stall control pongs
	// under KCP batching / SFU renegotiation; relax the pong timeout so a busy
	// link is not declared dead. Mirrors the client side. Conventional carriers
	// keep the conservative default (issue #95).
	if runtime.IsControlPlane(s.ln) && liveness.Timeout <= control.DefaultTimeout {
		liveness.Timeout = runtime.LivenessTimeout(s.ln)
	}
	onPong := liveness.OnPong
	onMissedPong := liveness.OnMissedPong
	onUnhealthy := liveness.OnUnhealthy
	liveness.OnPong = func(h control.Health) {
		s.sessMu.RLock()
		sid := s.sessionID
		s.sessMu.RUnlock()
		s.recordPong(h)
		logger.Debugf("control alive session=%s rtt=%v seq=%d", sid, h.RTT, h.Seq)
		if onPong != nil {
			onPong(h)
		}
	}
	liveness.OnMissedPong = func(missed int) {
		s.recordMissed(missed)
		logger.Warnf("control missed pong on server: missed_pongs=%d", missed)
		if onMissedPong != nil {
			onMissedPong(missed)
		}
	}
	liveness.OnUnhealthy = func(missed int) {
		s.recordUnhealthy(missed)
		logger.Warnf("control stream unhealthy on server: missed_pongs=%d", missed)
		if onUnhealthy != nil {
			onUnhealthy(missed)
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { _ = stream.Close() }()
		err := control.Run(controlCtx, stream, liveness)
		if controlCtx.Err() != nil || ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Warnf("server control stream ended: %v", err)
		}
		s.recordReconnect()
		logger.Infof("server reconnect reason=liveness - reinstalling smux session")
		s.resetLinkPeer()
		s.reinstallSession(sess)
		// Tell the carrier to rebuild itself too. Without this the SFU side
		// keeps its dead PC around and the client's reconnect handshakes
		// keep landing in the void until the carrier eventually notices on
		// its own (which observationally takes ~40s on a Telemost room).
		if s.ln != nil {
			s.ln.Reconnect("liveness")
		}
	}()
}

func (s *Server) startPeerControlLoop(ps *peerSession, stream *smux.Stream) {
	controlCtx, stop := context.WithCancel(context.Background())
	ps.controlStop = stop

	liveness := s.liveness
	// Control-plane carriers (vp8channel) can legitimately stall control pongs
	// under KCP batching / SFU renegotiation; relax the pong timeout so a busy
	// link is not declared dead. Mirrors the client side. Conventional carriers
	// keep the conservative default (issue #95).
	if runtime.IsControlPlane(s.ln) && liveness.Timeout <= control.DefaultTimeout {
		liveness.Timeout = runtime.LivenessTimeout(s.ln)
	}
	onPong := liveness.OnPong
	onMissedPong := liveness.OnMissedPong
	onUnhealthy := liveness.OnUnhealthy
	liveness.OnPong = func(h control.Health) {
		s.recordPong(h)
		logger.Debugf("control alive session=%s peer=%s rtt=%v seq=%d", ps.sessionID, ps.peerID, h.RTT, h.Seq)
		if onPong != nil {
			onPong(h)
		}
	}
	liveness.OnMissedPong = func(missed int) {
		s.recordMissed(missed)
		logger.Warnf("control missed pong on server: session=%s peer=%s missed_pongs=%d",
			ps.sessionID, ps.peerID, missed)
		if onMissedPong != nil {
			onMissedPong(missed)
		}
	}
	liveness.OnUnhealthy = func(missed int) {
		s.recordUnhealthy(missed)
		logger.Warnf("control stream unhealthy on server: session=%s peer=%s missed_pongs=%d",
			ps.sessionID, ps.peerID, missed)
		if onUnhealthy != nil {
			onUnhealthy(missed)
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { _ = stream.Close() }()
		err := control.Run(controlCtx, stream, liveness)
		if controlCtx.Err() != nil || s.stopping() {
			return
		}
		if err != nil {
			logger.Warnf("server control stream ended session=%s peer=%s: %v", ps.sessionID, ps.peerID, err)
		}
		s.recordReconnect()
		s.removePeerSession(ps.peerID, "reconnect")
	}()
}

func (s *Server) stopping() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Status returns the latest server-side control health snapshot.
func (s *Server) Status() control.Status {
	return s.health.Status()
}

func (s *Server) recordSession(sessionID string) { s.health.RecordSession(sessionID) }
func (s *Server) recordPong(h control.Health)    { s.health.RecordPong(h) }
func (s *Server) recordMissed(missed int)        { s.health.RecordMissed(missed) }
func (s *Server) recordUnhealthy(missed int)     { s.health.RecordUnhealthy(missed) }
func (s *Server) recordReconnect()               { s.health.RecordReconnect() }

func (s *Server) shutdown() {
	if s.done != nil {
		s.doneOnce.Do(func() { close(s.done) })
	}
	s.closeSession()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *Server) handleStream(_ context.Context, stream *smux.Stream, sessionID string) {
	defer func() { _ = stream.Close() }()
	if sessionID == "" {
		sessionID = s.currentSessionID()
	}

	// Read the connect JSON. The client writes the whole JSON in one
	// stream.Write so it usually arrives intact; tolerate fragmentation
	// by reading incrementally up to a sane cap.
	const maxConnReq = 4096
	header := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		n, err := stream.Read(tmp)
		if n > 0 {
			header = append(header, tmp[:n]...)
			if req, ok := parseConnectRequest(header); ok {
				_ = stream.SetReadDeadline(time.Time{})
				if req.Cmd == udpAssociateCommand {
					s.serveUDPAssociate(stream, sessionID)
					return
				}
				s.dispatch(stream, req, sessionID)
				return
			}
		}
		if err != nil {
			return
		}
		if len(header) > maxConnReq {
			return
		}
	}
}

func parseConnectRequest(buf []byte) (ConnectRequest, bool) {
	var req ConnectRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		return req, false
	}
	if req.Cmd != connectCommand && req.Cmd != udpAssociateCommand {
		return req, false
	}
	return req, true
}

// defaultAuthHook admits every client and assigns a random session ID.
// Replace it via [Config.AuthHook] to plug in real authorization.
func defaultAuthHook(_ string, _ map[string]any) (string, error) {
	return uuid.NewString(), nil
}

func (s *Server) dispatch(stream *smux.Stream, req ConnectRequest, sessionID string) {
	addr := net.JoinHostPort(req.Addr, strconv.Itoa(req.Port))
	logger.Infof("sid=%d connect %s", stream.ID(), addr)

	dialStart := time.Now()
	conn, err := s.dial(req)
	dialElapsed := time.Since(dialStart)

	if err != nil {
		logger.Infof("sid=%d dial %s failed (%v): %v", stream.ID(), addr, dialElapsed, err)
		return
	}
	defer func() { _ = conn.Close() }()

	logger.Infof("sid=%d connected %s in %v", stream.ID(), addr, dialElapsed)

	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}

	var bytesOut uint64
	done := make(chan struct{})
	go func() {
		n, _ := io.Copy(stream, conn)
		if n > 0 {
			bytesOut = uint64(n)
		}
		_ = stream.Close()
		close(done)
	}()
	in, _ := io.Copy(conn, stream)
	_ = conn.Close()
	<-done
	bytesIn := uint64(0)
	if in > 0 {
		bytesIn = uint64(in)
	}
	if s.onTraffic != nil {
		s.onTraffic(sessionID, addr, bytesIn, bytesOut)
	}
}

func (s *Server) dial(req ConnectRequest) (net.Conn, error) {
	addr := net.JoinHostPort(req.Addr, strconv.Itoa(req.Port))

	// Tunnel traffic priority: WARP > SOCKS > direct.
	// WARP wins so the VPS public IP isn't exposed to client traffic.
	proxyHost, proxyPort, proxyUser, proxyPass := "", 0, "", ""
	switch {
	case s.warpProxyAddr != "" && s.warpProxyPort > 0:
		proxyHost, proxyPort = s.warpProxyAddr, s.warpProxyPort
	case s.socksProxyAddr != "":
		proxyHost, proxyPort = s.socksProxyAddr, s.socksProxyPort
		proxyUser, proxyPass = s.socksProxyUser, s.socksProxyPass
	}

	if proxyHost == "" {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  s.resolver,
		}
		conn, err := dialer.Dial("tcp4", addr)
		if err != nil {
			return nil, fmt.Errorf("dial failed: %w", err)
		}
		return conn, nil
	}

	proxyAddr := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp4", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy: %w", err)
	}

	if err := s.socks5ConnectWithAuth(conn, req.Addr, req.Port, proxyUser, proxyPass); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// serveUDPAssociate runs the server side of the "udp-associate" relay: one
// smux stream carries length-prefixed datagram frames (the same framing the
// client uses in client.writeUDPRelayFrame) until either side closes. Each
// distinct destination gets a persistent connected UDP socket in a small
// NAT table; a reader goroutine pumps replies from that socket back onto
// the stream, so multi-packet flows (QUIC, VoIP, games) work — one-shot
// per-datagram dials could only ever return a single reply. The relay dials
// with the instance resolver so tunneled names resolve through the same DNS
// as TCP traffic.
func (s *Server) serveUDPAssociate(stream *smux.Stream, sessionID string) {
	defer func() { _ = stream.Close() }()
	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}
	logger.Infof("sid=%d udp-associate opened session=%s", stream.ID(), sessionID)
	nat := newUDPNatTable(stream, s.resolver, udpNatIdleTimeout)
	defer nat.closeAll()
	// Zero-payload frames keep the client's stream read deadline from
	// expiring during silence (muted call, idle QUIC session).
	keepaliveStop := make(chan struct{})
	defer close(keepaliveStop)
	go func() {
		ticker := time.NewTicker(udpKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-keepaliveStop:
				return
			case <-ticker.C:
				if err := nat.writeKeepalive(); err != nil {
					return
				}
			}
		}
	}()
	for {
		_ = stream.SetReadDeadline(time.Now().Add(udpRelayStreamTimeout))
		addr, port, payload, err := readUDPRelayFrame(stream)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			// Zero-payload frames are keepalives the client sends to keep
			// the stream's read deadline from expiring during silence.
			continue
		}
		if err := nat.send(addr, port, payload); err != nil {
			logger.Debugf("sid=%d udp-associate relay failed: %v", stream.ID(), err)
		}
	}
}

// udpNatTable maps one relay destination to a persistent connected UDP
// socket, keyed per smux stream. Readers run per socket and frame replies
// back onto the stream; idle sockets are reaped by send() so a dead peer
// cannot leak one socket per datagram. writeMu serializes frame writes:
// smux splits large Writes into multiple wire frames, so interleaved
// keepalive and reply writes would corrupt the framing.
type udpNatTable struct {
	mu       sync.Mutex
	writeMu  sync.Mutex
	stream   *smux.Stream
	resolver *net.Resolver
	idle     time.Duration
	entries  map[string]*udpNatEntry
}

type udpNatEntry struct {
	conn *net.UDPConn
	last time.Time
}

func newUDPNatTable(stream *smux.Stream, resolver *net.Resolver, idle time.Duration) *udpNatTable {
	return &udpNatTable{
		stream:   stream,
		resolver: resolver,
		idle:     idle,
		entries:  make(map[string]*udpNatEntry),
	}
}

// writeKeepalive emits one zero-payload relay frame so the client's stream
// read deadline keeps sliding while the app is silent.
func (n *udpNatTable) writeKeepalive() error {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	_ = n.stream.SetWriteDeadline(time.Now().Add(udpRelayWriteTimeout))
	return writeUDPRelayFrame(n.stream, "", 0, nil)
}

// send forwards one datagram to its destination, dialing a persistent socket
// on first use, and reaps entries idle beyond the table timeout.
func (n *udpNatTable) send(addr string, port int, payload []byte) error {
	hostPort := net.JoinHostPort(addr, strconv.Itoa(port))
	n.mu.Lock()
	entry, ok := n.entries[hostPort]
	if ok && time.Since(entry.last) > n.idle {
		// The reader goroutine timed out or the socket died; redial below.
		ok = false
		_ = entry.conn.Close()
		delete(n.entries, hostPort)
	}
	if !ok {
		// Resolve through the instance DNS (same path as TCP traffic) so
		// domain destinations from the SOCKS5 header work.
		ips, err := n.resolver.LookupIP(context.Background(), "ip", addr)
		if err != nil || len(ips) == 0 {
			n.mu.Unlock()
			return fmt.Errorf("resolve %s: %v", addr, err)
		}
		udpAddr := &net.UDPAddr{IP: ips[0], Port: port}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			n.mu.Unlock()
			return fmt.Errorf("udp dial %s: %w", hostPort, err)
		}
		entry = &udpNatEntry{conn: conn}
		n.entries[hostPort] = entry
		go n.readLoop(entry, udpAddr)
	}
	entry.last = time.Now()
	conn := entry.conn
	n.mu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(udpRelayWriteTimeout))
	if _, err := conn.Write(payload); err != nil {
		// Drop the entry so the next datagram dials a fresh socket instead
		// of piling onto a broken one.
		n.mu.Lock()
		if current, still := n.entries[hostPort]; still && current == entry {
			_ = entry.conn.Close()
			delete(n.entries, hostPort)
		}
		n.mu.Unlock()
		return fmt.Errorf("udp write %s: %w", hostPort, err)
	}
	return nil
}

// readLoop pumps replies from one persistent socket back onto the relay
// stream until the socket is closed by reaping or table teardown.
func (n *udpNatTable) readLoop(entry *udpNatEntry, udpAddr *net.UDPAddr) {
	defer func() { _ = entry.conn.Close() }()
	addr := udpAddr.IP.String()
	port := udpAddr.Port
	buf := make([]byte, udpRelayFrameCap)
	for {
		_ = entry.conn.SetReadDeadline(time.Now().Add(n.idle))
		m, err := entry.conn.Read(buf)
		if err != nil {
			return
		}
		n.writeMu.Lock()
		_ = n.stream.SetWriteDeadline(time.Now().Add(udpRelayWriteTimeout))
		err = writeUDPRelayFrame(n.stream, addr, port, buf[:m])
		n.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (n *udpNatTable) closeAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for key, entry := range n.entries {
		_ = entry.conn.Close()
		delete(n.entries, key)
	}
}

// udpRelayFrameCap bounds one relay datagram on the wire (payload plus the
// small address header). Sized for a full-size UDP payload; anything larger
// is a protocol error, not a datagram we should fragment.
const udpRelayFrameCap = 64 * 1024

// UDP relay pacing knobs. The stream deadline must exceed the client's
// keepalive interval (client sends a zero-payload frame every 30 s during
// silence); NAT sockets idle out well before the table grows unbounded.
const (
	udpRelayStreamTimeout = 5 * time.Minute
	udpRelayWriteTimeout  = 30 * time.Second
	udpNatIdleTimeout     = 2 * time.Minute
	udpKeepaliveInterval  = 30 * time.Second
)

// writeUDPRelayFrame encodes one datagram: [u32 total][u16 addrLen][addr]
// [u16 port][payload]. Mirrors client.writeUDPRelayFrame; both sides must
// stay in lockstep because there is no version byte on this sub-protocol.
func writeUDPRelayFrame(w io.Writer, addr string, port int, payload []byte) error {
	frame := make([]byte, 0, 4+len(addr)+len(payload))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(addr))) //nolint:gosec // G115: datagram addr, bounded by frame cap
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

func (s *Server) socks5Connect(conn net.Conn, targetAddr string, targetPort int) error {
	return s.socks5ConnectWithAuth(conn, targetAddr, targetPort, s.socksProxyUser, s.socksProxyPass)
}

func (s *Server) socks5ConnectWithAuth(conn net.Conn, targetAddr string, targetPort int, proxyUser, proxyPass string) error {
	if proxyUser != "" {
		// Offer username/password auth (RFC 1929) only.
		if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
			return fmt.Errorf("failed to write socks5 auth: %w", err)
		}
	} else {
		// No authentication.
		if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
			return fmt.Errorf("failed to write socks5 auth: %w", err)
		}
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read socks5 auth resp: %w", err)
	}
	if resp[0] != 5 {
		return ErrSocks5AuthFailed
	}
	switch resp[1] {
	case 0: // no auth accepted
		if proxyUser != "" {
			return ErrSocks5AuthFailed
		}
	case 2: // username/password
		user := proxyUser
		pass := proxyPass
		if len(user) > 255 {
			user = user[:255]
		}
		if len(pass) > 255 {
			pass = pass[:255]
		}
		authMsg := make([]byte, 0, 3+len(user)+len(pass))
		authMsg = append(authMsg, 1, byte(len(user)))
		authMsg = append(authMsg, []byte(user)...)
		authMsg = append(authMsg, byte(len(pass)))
		authMsg = append(authMsg, []byte(pass)...)
		if _, err := conn.Write(authMsg); err != nil {
			return fmt.Errorf("failed to write socks5 credentials: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("failed to read socks5 credentials resp: %w", err)
		}
		if authResp[1] != 0 {
			return ErrSocks5AuthFailed
		}
	default:
		return ErrSocks5AuthFailed
	}

	addrLen := len(targetAddr)
	if addrLen > 255 {
		addrLen = 255
		targetAddr = targetAddr[:255]
	}

	req := make([]byte, 0, 7+addrLen)
	req = append(req, 5, 1, 0, 3, byte(addrLen))
	req = append(req, []byte(targetAddr)...)
	req = append(req, byte(targetPort>>8), byte(targetPort)) //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to write socks5 connect req: %w", err)
	}

	resp = make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read socks5 connect resp: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		return fmt.Errorf("%w: %d", ErrSocks5ConnectFailed, resp[1])
	}

	return nil
}
