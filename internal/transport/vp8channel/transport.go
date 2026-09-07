// Package vp8channel disguises a KCP-based byte transport as a stream of
// valid VP8 keyframes so SFUs that validate bitstream conformance let the
// payload through. The package owns its own KCP framing; the per-message
// fragment/ack machinery used by videochannel/seichannel is unnecessary
// here because KCP already provides ordered, reliable delivery.
package vp8channel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	enginebuiltin "github.com/openlibrecommunity/olcrtc/internal/engine/builtin"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/transport/common"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	defaultMaxPayloadSize = 60 * 1024
	defaultConnectTimeout = 60 * time.Second
	rtpBufSize = 65536
	// outboundQueueSize bounds KCP packets waiting for the paced writer. Sized
	// to a couple of send windows so KCP's flush never blocks (a blocked
	// WriteTo would stall KCP's update loop and delay ACKs); the paced writer
	// keeps it drained so this depth is headroom, not standing latency.
	outboundQueueSize    = 2048
	inboundQueueSize     = 8192
	canSendHighWatermark = 90 // percent
	keepaliveIdlePeriod  = 100 * time.Millisecond
	// defaultPeerRestartGrace is how long the latched peer must be silent before
	// a frame from a different epoch is read as a restarted peer/server. A live
	// peer emits decodable keepalives, so a few missed beats is a useful signal
	// without waiting for the full relaxed liveness window.
	defaultPeerRestartGrace = 6 * time.Second

	// minSampleDuration floors the wall-clock duration passed to WriteSample
	// (~3 ticks of the 90 kHz VP8 clock) so two back-to-back writes still
	// advance the track's RTP timestamp by at least one tick — keeping it
	// strictly monotonic without re-introducing meaningful drift. See
	// writeTrackSample.
	minSampleDuration = time.Second / 30000

	// peerIdleTimeout bounds how long a server-side peer KCP session survives
	// with zero inbound frames before the janitor evicts it. A live peer emits
	// a VP8 keepalive every keepaliveIdlePeriod, so any epoch silent this long
	// has been abandoned: the client rotated its epoch on carrier reconnect /
	// ResetPeer and will never return on the old one. Set well above the
	// relaxed liveness teardown window (~75s) so a peer that legitimately
	// stalls during SFU renegotiation while keeping its epoch stable is never
	// reaped mid-recovery. Without eviction every rotation leaks a zombie peer
	// session (its own KCP runtime + writer pump) and the count grows unbounded
	// under a reconnect storm.
	peerIdleTimeout     = 120 * time.Second
	peerJanitorInterval = 30 * time.Second
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("vp8channel transport closed")
)

var vp8Keepalive = []byte{ //nolint:gochecknoglobals // package-level state intentional
	0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
	0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
	0x99, 0x84, 0x88, 0xfc,
}

// KCP data frames are disguised as valid VP8 frames so Telemost SFU lets them
// through. The SFU validates the VP8 bitstream and drops frames that don't
// look like real VP8 - so we prepend the keepalive keyframe and append our
// header + payload after it. Wire layout:
//
//	[0..20]    = vp8Keepalive (valid VP8 keyframe, passes SFU inspection)
//	[20..24]   = binding token derived from client-id (big-endian uint32)
//	[24..28]   = sender's session epoch (big-endian uint32)
//	[28..32]   = CRC32(token || epoch)
//	[32..]     = raw KCP packet bytes
const (
	tokenOff    = 20
	epochOff    = 24
	crcOff      = 28
	epochHdrLen = 32
)

var kcpBatchMagic = [4]byte{'O', 'L', 'K', 'B'} //nolint:gochecknoglobals // wire marker

// videoSession is the subset of engine.Session + engine.VideoTrackCapable
// the vp8channel transport relies on.
type videoSession interface {
	Connect(ctx context.Context) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
	Reconnect(reason string)
	AddTrack(track webrtc.TrackLocal) error
	SetTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver))
}

type streamTransport struct {
	stream        videoSession
	track         *webrtc.TrackLocalStaticSample
	onData        func([]byte)
	onPeerData    func(peerID string, data []byte)
	outbound      chan []byte
	closeCh       chan struct{}
	writerDone    chan struct{}
	closed        atomic.Bool
	writerUp      atomic.Bool
	writerOnce    sync.Once
	kcpOnce       sync.Once
	frameInterval time.Duration
	batchSize     int
	perTickBytes  int

	// writeMu serializes WriteSample across the keepalive writerLoop and every
	// per-peer writer pump, and guards lastWrite so the shared track's RTP
	// timestamp advances by real elapsed time rather than by the number of
	// WriteSample calls. See writeTrackSample.
	writeMu   sync.Mutex
	lastWrite time.Time

	// localEpoch is stamped into every outgoing VP8 frame. Explicit
	// upper-layer resets rotate it so the peer can reset its KCP state too.
	// Peer-triggered resets keep it stable to avoid reset ping-pong.
	bindingToken uint32
	epochMu      sync.RWMutex
	localEpoch   uint32
	peerEpoch    atomic.Uint32

	// lastPeerFrameNano stamps the most recent frame from the latched peer.
	// peerRestarting prevents repeated carrier rebuilds while one restart is
	// already in flight.
	lastPeerFrameNano atomic.Int64
	peerRestarting    atomic.Bool
	peerRestartGrace  time.Duration

	kcp           *kcpRuntime
	kcpMu         sync.RWMutex
	reconnectMu   sync.Mutex
	reconnectFn   func()
	peerConfirmed atomic.Bool

	// Multi-peer support: when onPeerData is set, each remote epoch gets
	// its own KCP runtime and data is routed via onPeerData(peerID, ...).
	peersMu  sync.RWMutex
	peers    map[uint32]*kcpRuntime   // epoch → KCP runtime
	peerOut  map[uint32]chan []byte   // epoch → outbound queue
	peerStop map[uint32]chan struct{} // epoch → writer-pump stop signal
	peerSeen map[uint32]*atomic.Int64 // epoch → last inbound frame (unix nanos)
}

// New creates a vp8channel transport backed by a carrier engine.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	opts, err := optionsFrom(cfg)
	if err != nil {
		return nil, err
	}

	session, err := enginebuiltin.Open(ctx, cfg.Carrier, enginebuiltin.Config{
		RoomURL:   cfg.RoomURL,
		Name:      cfg.Name,
		OnData:    nil,
		DNSServer: cfg.DNSServer,
		ProxyAddr: cfg.ProxyAddr,
		ProxyPort: cfg.ProxyPort,
		Insecure:  cfg.Insecure,
		Engine:    cfg.Engine,
		URL:       cfg.URL,
		Token:     cfg.Token,
	})
	if err != nil {
		return nil, fmt.Errorf("open engine session: %w", err)
	}

	vt, ok := session.(engine.VideoTrackCapable)
	if !ok || !session.Capabilities().VideoTrack {
		_ = session.Close()
		return nil, ErrVideoTrackUnsupported
	}
	stream := &engineVideoSession{session: session, vt: vt}

	// Stream/track IDs must be unique per peer — Jitsi rejects session-accept
	// when msid collides with another participant in the conference.
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		"vp8channel-"+common.RandomID(),
		"olcrtc-"+common.RandomID(),
	)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	tr := newStreamTransport(stream, track, cfg, opts)

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

func newStreamTransport(
	stream *engineVideoSession,
	track *webrtc.TrackLocalStaticSample,
	cfg transport.Config,
	opts Options,
) *streamTransport {
	fps := opts.FPS
	batchSize := opts.BatchSize
	if fps <= 0 {
		fps = defaultFPS
	}
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	byteRate := opts.MaxBytesPerSec
	if byteRate <= 0 {
		byteRate = defaultMaxBytesPerSec
	}
	// Bytes we may emit per frame tick when a user explicitly enables a rate
	// cap. With the default zero cap, allow a full VP8 payload each tick so the
	// writer does not become a hidden throughput throttle.
	perTickBytes := defaultMaxPayloadSize
	if byteRate > 0 {
		perTickBytes = byteRate / fps
		if perTickBytes < epochHdrLen {
			perTickBytes = epochHdrLen
		}
	}

	tr := &streamTransport{
		stream:        stream,
		track:         track,
		onData:        cfg.OnData,
		onPeerData:    cfg.OnPeerData,
		outbound:      make(chan []byte, outboundQueueSize),
		closeCh:       make(chan struct{}),
		writerDone:    make(chan struct{}),
		frameInterval: time.Second / time.Duration(fps),
		batchSize:     batchSize,
		perTickBytes:  perTickBytes,
		bindingToken:  bindingToken(cfg.RoomURL),
		localEpoch:    randomEpoch(),
		peers:         make(map[uint32]*kcpRuntime),
		peerOut:       make(map[uint32]chan []byte),
		peerStop:      make(map[uint32]chan struct{}),
		peerSeen:         make(map[uint32]*atomic.Int64),
		peerRestartGrace: defaultPeerRestartGrace,
	}

	// In single-peer mode, confirm the peer epoch on first successful KCP
	// delivery. This ensures we latch on the server (which completes
	// handshake) rather than another client whose frames arrive first.
	if cfg.OnData != nil && cfg.OnPeerData == nil {
		inner := cfg.OnData
		tr.onData = func(data []byte) {
			if !tr.peerConfirmed.Swap(true) {
				epoch := tr.peerEpoch.Load()
				logger.Infof("vp8channel: peer confirmed epoch=0x%08x", epoch)
			}
			inner(data)
		}
	} else {
		tr.onData = cfg.OnData
	}

	// Multi-peer (server) mode accretes a peer KCP session per remote epoch;
	// reap abandoned ones so a client reconnect storm cannot leak them.
	if tr.onPeerData != nil {
		go tr.peerJanitor()
	}

	return tr
}

func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	// Start KCP eagerly so Send/CanSend work immediately after Connect.
	// Without this, the handshake round-trip that runs right after Connect
	// would deadlock: muxconn.Write spins on CanSend (which checks kcp!=nil)
	// and KCP was only started lazily on the first incoming peer frame.
	p.kcpOnce.Do(func() {
		rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
		if err != nil {
			logger.Infof("vp8channel: startKCP failed: %v", err)
			return
		}
		p.kcpMu.Lock()
		p.kcp = rt
		p.kcpMu.Unlock()
		logger.Infof("vp8channel: KCP started localEpoch=0x%08x", p.localEpochValue())
	})

	p.writerOnce.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// epochHeader returns the 5-byte VP8-frame header used to tag every KCP
// packet sent in the current local session.
func (p *streamTransport) epochHeader() [epochHdrLen]byte {
	p.epochMu.RLock()
	epoch := p.localEpoch
	p.epochMu.RUnlock()
	return buildEpochHeader(p.bindingToken, epoch)
}

func buildEpochHeader(token, epoch uint32) [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:epochOff], token)
	binary.BigEndian.PutUint32(hdr[epochOff:crcOff], epoch)
	binary.BigEndian.PutUint32(hdr[crcOff:epochHdrLen], epochCRC(token, epoch))
	return hdr
}

func (p *streamTransport) rotateEpochHeader() [epochHdrLen]byte {
	p.epochMu.Lock()
	for {
		next := randomEpoch()
		if next != p.localEpoch {
			p.localEpoch = next
			break
		}
	}
	epoch := p.localEpoch
	p.epochMu.Unlock()
	return buildEpochHeader(p.bindingToken, epoch)
}

func (p *streamTransport) localEpochValue() uint32 {
	p.epochMu.RLock()
	defer p.epochMu.RUnlock()
	return p.localEpoch
}

func epochCRC(token, epoch uint32) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[0:4], token)
	binary.BigEndian.PutUint32(buf[4:8], epoch)
	return crc32.ChecksumIEEE(buf[:])
}

func parseEpochHeader(frame []byte) (uint32, uint32, bool) {
	if len(frame) < epochHdrLen {
		return 0, 0, false
	}
	token := binary.BigEndian.Uint32(frame[tokenOff:epochOff])
	epoch := binary.BigEndian.Uint32(frame[epochOff:crcOff])
	gotCRC := binary.BigEndian.Uint32(frame[crcOff:epochHdrLen])
	return token, epoch, gotCRC == epochCRC(token, epoch)
}

func bindingToken(clientID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientID))
	token := h.Sum32()
	if token == 0 {
		token = 1
	}
	return token
}

func randomEpoch() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux essentially never fails; fall back to a
		// time-derived value rather than panic.
		return uint32(time.Now().UnixNano()) //nolint:gosec // G115: bounded conversion verified by surrounding logic
	}
	e := binary.BigEndian.Uint32(b[:])
	if e == 0 {
		e = 1
	}
	return e
}

func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}

	return rt.send(data)
}

// SendTo transmits data to a specific peer identified by its epoch hex string.
func (p *streamTransport) SendTo(peerID string, data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return fmt.Errorf("vp8channel: invalid peerID %q: %w", peerID, err)
	}
	p.peersMu.RLock()
	rt := p.peers[epoch]
	p.peersMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}
	return rt.send(data)
}

// SupportsPeerRouting reports whether this transport can address individual peers.
func (p *streamTransport) SupportsPeerRouting() bool {
	return p.onPeerData != nil
}

// DropPeer immediately removes a server-side peer epoch after its tunnel
// session closes, so a reconnect cannot reuse buffered KCP/control frames.
func (p *streamTransport) DropPeer(peerID string) {
	epoch, err := parsePeerID(peerID)
	if err == nil {
		p.evictPeer(epoch)
	}
}

func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)

		p.kcpMu.RLock()
		rt := p.kcp
		p.kcpMu.RUnlock()
		if rt != nil {
			rt.close()
		}

		p.peersMu.Lock()
		for _, prt := range p.peers {
			prt.close()
		}
		p.peers = make(map[uint32]*kcpRuntime)
		p.peerOut = make(map[uint32]chan []byte)
		p.peerStop = make(map[uint32]chan struct{})
		p.peerSeen = make(map[uint32]*atomic.Int64)
		p.peersMu.Unlock()

		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

func (p *streamTransport) drainOutbound() {
	for {
		select {
		case <-p.outbound:
		default:
			return
		}
	}
}

// ResetPeer drops queued KCP traffic and starts a fresh KCP state machine while
// keeping the carrier connection alive. The client/server liveness layer calls
// this before rebuilding smux so replacement handshakes are not parsed behind
// stale bytes from streams that were active when the old session died.
func (p *streamTransport) ResetPeer() {
	p.peerConfirmed.Store(false)
	p.peerEpoch.Store(0)
	p.restartKCP(p.rotateEpochHeader())
}

// Reconnect forwards to the underlying engine session.
func (p *streamTransport) Reconnect(reason string) {
	p.stream.Reconnect(reason)
}

func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.reconnectMu.Lock()
	p.reconnectFn = cb
	p.reconnectMu.Unlock()
	p.stream.SetReconnectCallback(func() {
		p.resetKCP()
		if cb != nil {
			cb()
		}
	})
}

func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.stream.SetShouldReconnect(fn)
}

func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.stream.SetEndedCallback(cb)
}

func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.stream.WatchConnection(ctx)
}

// WaitForPeer blocks until the remote peer epoch has been observed. Waiting
// here prevents the initial smux SYN from racing ahead of the server bridge on
// SFU-backed video transports.
func (p *streamTransport) WaitForPeer(ctx context.Context) error {
	const pollInterval = 50 * time.Millisecond
	for {
		if p.peerEpoch.Load() != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (p *streamTransport) CanSend() bool {
	if p.closed.Load() {
		return false
	}
	p.kcpMu.RLock()
	hasKCP := p.kcp != nil
	p.kcpMu.RUnlock()
	return hasKCP && p.stream.CanSend() &&
		len(p.outbound) < cap(p.outbound)*canSendHighWatermark/100
}

// Features advertises reliable+ordered semantics now that KCP guarantees
// in-order delivery with retransmits. The upper layer (mux/curl tunnel)
// can rely on these properties end-to-end.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayloadSize,
	}
}

// UseRelaxedLiveness opts vp8channel into the relaxed smux keep-alive and
// control liveness windows: KCP batching and SFU publisher-PC renegotiation
// can legitimately go silent for ~25-30s, which must not be mistaken for a
// dead link (issue #95).
func (p *streamTransport) UseRelaxedLiveness() bool {
	return true
}

// writeTrackSample emits one VP8 sample to the shared local track, deriving
// the sample Duration from wall-clock time elapsed since the previous write.
//
// pion advances a track's RTP timestamp by Duration*clockRate per WriteSample,
// so a fixed Duration makes the RTP clock a function of *call frequency*, not
// real time: idle keepalives (~10/s) run it slow, and the unpaced per-peer
// writer pump bursts (one WriteSample per KCP segment) run it fast — racing the
// timestamp ahead of wall-clock ("into the future"). Telemost's SFU validates
// RTP/RTCP timestamp progression and silently stops forwarding a track whose
// clock has drifted, black-holing the tunnel while ICE stays healthy (the
// server->client direction dies first, the client then rotates its epoch).
// Using real elapsed time keeps the RTP timestamp linear with wall-clock no
// matter how often, or from how many goroutines, samples are written.
func (p *streamTransport) writeTrackSample(data []byte) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	dur := p.frameInterval
	now := time.Now()
	if !p.lastWrite.IsZero() {
		if dur = now.Sub(p.lastWrite); dur < minSampleDuration {
			dur = minSampleDuration
		}
	}
	p.lastWrite = now

	_ = p.track.WriteSample(media.Sample{
		Data:     data,
		Duration: dur,
	})
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	keepaliveEvery := max(int(keepaliveIdlePeriod/p.frameInterval), 1)
	forceKeepaliveEvery := max(int((2*time.Second)/p.frameInterval), 1)
	idleTicks := 0
	ticksSinceKeepalive := 0

	for {
		select {
		case <-p.closeCh:
			return
		case frame := <-p.outbound:
			// Data path: never wait for the next tick when KCP already has
			// bytes queued. Coalescing back-to-back frames here only adds up
			// to one frameInterval of latency per message for zero wire
			// savings — the batcher drains the queue non-blockingly below.
			ticksSinceKeepalive++
			if ticksSinceKeepalive >= forceKeepaliveEvery {
				ticksSinceKeepalive = 0
				hdr := p.epochHeader()
				p.writeTrackSample(hdr[:])
			}
			p.writeTrackSample(p.batchSample(frame, p.perTickBytes))
			idleTicks = 0
		case <-ticker.C:
			ticksSinceKeepalive++
			if ticksSinceKeepalive >= forceKeepaliveEvery {
				ticksSinceKeepalive = 0
				hdr := p.epochHeader()
				p.writeTrackSample(hdr[:])
			}

			var sample []byte
			select {
			case frame := <-p.outbound:
				sample = p.batchSample(frame, p.perTickBytes)
				idleTicks = 0
			default:
				idleTicks++
				if idleTicks < keepaliveEvery {
					continue
				}
				idleTicks = 0
				hdr := p.epochHeader()
				sample = hdr[:]
			}

			p.writeTrackSample(sample)
		}
	}
}

func (p *streamTransport) batchSample(first []byte, maxBytes int) []byte {
	return p.batchSampleFrom(p.outbound, first, maxBytes)
}

func (p *streamTransport) batchSampleFrom(src <-chan []byte, first []byte, maxBytes int) []byte {
	if maxBytes <= 0 || maxBytes > defaultMaxPayloadSize {
		maxBytes = defaultMaxPayloadSize
	}
	if len(first) <= epochHdrLen || p.batchSize <= 1 {
		return first
	}

	sample := make([]byte, 0, defaultMaxPayloadSize)
	sample = append(sample, first[:epochHdrLen]...)
	sample = append(sample, kcpBatchMagic[:]...)
	sample = appendBatchPacket(sample, first[epochHdrLen:])

	for packets := 1; packets < p.batchSize; packets++ {
		select {
		case frame := <-src:
			if len(frame) <= epochHdrLen {
				continue
			}
			payload := frame[epochHdrLen:]
			if len(sample)+2+len(payload) > maxBytes {
				return sample
			}
			sample = appendBatchPacket(sample, payload)
		default:
			return sample
		}
	}
	return sample
}

func appendBatchPacket(dst, packet []byte) []byte {
	if len(packet) > 0xffff {
		return dst
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet))) //nolint:gosec // bounded above
	dst = append(dst, lenBuf[:]...)
	return append(dst, packet...)
}

func (p *streamTransport) resetKCP() {
	p.peerConfirmed.Store(false)
	p.peerEpoch.Store(0)
	p.restartKCP(p.rotateEpochHeader())
}

func (p *streamTransport) restartKCP(epochHdr [epochHdrLen]byte) {
	p.drainOutbound()
	p.kcpMu.Lock()
	old := p.kcp
	p.kcp = nil
	p.kcpMu.Unlock()
	if old != nil {
		old.close()
	}
	rt, err := startKCP(p.outbound, p.onData, epochHdr)
	if err != nil {
		return
	}
	p.kcpMu.Lock()
	p.kcp = rt
	p.kcpMu.Unlock()
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		go p.drainTrack(track)
		return
	}

	// We don't reset KCP here. Peer restarts are detected by the epoch
	// header on incoming frames, which works even when the SFU keeps
	// forwarding the same track across our restarts.
	go p.readVP8Track(track)
}

func (p *streamTransport) drainTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, rtpBufSize)
	for {
		if _, _, err := track.Read(buf); err != nil {
			return
		}
	}
}

const reorderWindow = 256

func seqLess(a, b uint16) bool {
	return (a-b)&0x8000 != 0
}

type reorderBuffer struct {
	pkts    map[uint16]*rtp.Packet
	nextSeq uint16
	started bool
}

func newReorderBuffer() *reorderBuffer {
	return &reorderBuffer{pkts: make(map[uint16]*rtp.Packet, reorderWindow)}
}

func (b *reorderBuffer) push(pkt *rtp.Packet) []*rtp.Packet {
	if !b.started {
		b.started = true
		b.nextSeq = pkt.SequenceNumber
	}
	if seqLess(pkt.SequenceNumber, b.nextSeq) {
		return nil
	}
	cp := &rtp.Packet{Header: pkt.Header}
	cp.Payload = append([]byte(nil), pkt.Payload...)
	b.pkts[pkt.SequenceNumber] = cp
	if len(b.pkts) > reorderWindow {
		b.skipToOldest()
	}
	return b.drain()
}

func (b *reorderBuffer) drain() []*rtp.Packet {
	var out []*rtp.Packet
	for {
		pkt, ok := b.pkts[b.nextSeq]
		if !ok {
			return out
		}
		out = append(out, pkt)
		delete(b.pkts, b.nextSeq)
		b.nextSeq++
	}
}

func (b *reorderBuffer) skipToOldest() {
	first := true
	var oldest uint16
	for seq := range b.pkts {
		if first || seqLess(seq, oldest) {
			oldest = seq
			first = false
		}
	}
	b.nextSeq = oldest
}

type vp8FrameState struct {
	vp8Pkt      codecs.VP8Packet
	frameBuf    []byte
	lastSeq     uint16
	haveLastSeq bool
	frameValid  bool
}

// processRTPPacket returns a complete VP8 frame payload when fully assembled,
// nil otherwise. Detects packet loss/reordering to avoid silently corrupting
// fragmented VP8 frames.
func (s *vp8FrameState) processRTPPacket(pkt *rtp.Packet) []byte {
	if s.haveLastSeq && pkt.SequenceNumber != s.lastSeq+1 {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
	}
	s.lastSeq = pkt.SequenceNumber
	s.haveLastSeq = true

	vp8Payload, err := s.vp8Pkt.Unmarshal(pkt.Payload)
	if err != nil {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
		return nil
	}

	if s.vp8Pkt.S == 1 {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = true
	}

	if !s.frameValid {
		return nil
	}

	s.frameBuf = append(s.frameBuf, vp8Payload...)

	if !pkt.Marker {
		return nil
	}

	defer func() {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = false
	}()

	if len(s.frameBuf) >= epochHdrLen {
		frame := make([]byte, len(s.frameBuf))
		copy(frame, s.frameBuf)
		return frame
	}
	return nil
}

func (p *streamTransport) readVP8Track(track *webrtc.TrackRemote) {
	var state vp8FrameState
	reorder := newReorderBuffer()
	buf := make([]byte, rtpBufSize)

	for {
		n, _, err := track.Read(buf)
		if err != nil {
			return
		}

		pkt := &rtp.Packet{}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}

		for _, ordered := range reorder.push(pkt) {
			frame := state.processRTPPacket(ordered)
			if frame == nil {
				continue
			}
			p.handleIncomingFrame(frame)
		}
	}
}

func (p *streamTransport) handleFirstPeer(peerEpoch uint32) {
	p.peerEpoch.Store(peerEpoch)
	p.peerConfirmed.Store(true)
	p.lastPeerFrameNano.Store(time.Now().UnixNano())
	p.peerRestarting.Store(false)
	logger.Infof("vp8channel: peer latched epoch=0x%08x", peerEpoch)
}

// handleIncomingFrame parses the epoch header and delivers KCP payload.
func (p *streamTransport) handleIncomingFrame(frame []byte) {
	frameToken, peerEpoch, ok := parseEpochHeader(frame)
	if !ok {
		return
	}
	if frameToken != p.bindingToken {
		return
	}
	kcpPayload := frame[epochHdrLen:]
	if peerEpoch == p.localEpochValue() {
		return
	}

	// Multi-peer mode: route each epoch to its own KCP runtime.
	if p.onPeerData != nil {
		p.handlePeerFrame(peerEpoch, kcpPayload)
		return
	}

	// Single-peer mode: latch on first epoch seen. If the latched peer has
	// gone silent and a different epoch appears, treat it as a peer/server
	// restart and rebuild the carrier instead of waiting for liveness timeout.
	if !p.peerConfirmed.Load() {
		p.handleFirstPeer(peerEpoch)
	} else if prev := p.peerEpoch.Load(); prev != peerEpoch {
		p.maybePeerRestart(peerEpoch)
		return
	} else {
		p.lastPeerFrameNano.Store(time.Now().UnixNano())
	}

	if len(kcpPayload) == 0 {
		return
	}
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt != nil {
		deliverKCPPayload(rt, kcpPayload)
	}
}

// maybePeerRestart reads a frame from a non-latched epoch as a peer/server
// restart once the latched peer has been silent longer than peerRestartGrace.
// Recovery uses the carrier reconnect path because a restarted server joins
// the SFU as a fresh participant; a local-only KCP reset on the stale media
// path can otherwise wait until the relaxed liveness window expires.
func (p *streamTransport) maybePeerRestart(src uint32) {
	if p.peerRestartGrace <= 0 {
		return
	}
	last := p.lastPeerFrameNano.Load()
	if last == 0 || time.Since(time.Unix(0, last)) < p.peerRestartGrace {
		return
	}
	if !p.peerRestarting.CompareAndSwap(false, true) {
		return
	}
	logger.Infof("vp8channel: peer restart detected old=0x%08x new=0x%08x - rebuilding carrier",
		p.peerEpoch.Load(), src)
	go p.stream.Reconnect("peer restart")
}

// handlePeerFrame routes incoming KCP data to a per-peer KCP runtime,
// creating one on demand. Each peer epoch gets its own independent KCP
// session so multiple clients can coexist in the same room.
func (p *streamTransport) handlePeerFrame(peerEpoch uint32, kcpPayload []byte) {
	if len(kcpPayload) == 0 {
		// Keepalive — ensure peer is registered but nothing to deliver.
		p.getOrCreatePeerKCP(peerEpoch)
		return
	}

	rt := p.getOrCreatePeerKCP(peerEpoch)
	if rt != nil {
		deliverKCPPayload(rt, kcpPayload)
	}
}

func (p *streamTransport) getOrCreatePeerKCP(epoch uint32) *kcpRuntime {
	now := time.Now().UnixNano()
	p.peersMu.RLock()
	rt := p.peers[epoch]
	if seen := p.peerSeen[epoch]; seen != nil {
		seen.Store(now)
	}
	p.peersMu.RUnlock()
	if rt != nil {
		return rt
	}

	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	// Double-check after acquiring write lock.
	if rt := p.peers[epoch]; rt != nil {
		return rt
	}

	peerID := formatPeerID(epoch)
	out := make(chan []byte, outboundQueueSize)
	hdr := buildEpochHeader(p.bindingToken, p.localEpochValue())
	rt, err := startKCP(out, func(data []byte) {
		if p.onPeerData != nil {
			p.onPeerData(peerID, data)
		}
	}, hdr)
	if err != nil {
		logger.Warnf("vp8channel: startKCP for peer 0x%08x failed: %v", epoch, err)
		return nil
	}
	stop := make(chan struct{})
	seen := &atomic.Int64{}
	seen.Store(now)
	p.peers[epoch] = rt
	p.peerOut[epoch] = out
	p.peerStop[epoch] = stop
	p.peerSeen[epoch] = seen
	logger.Infof("vp8channel: peer session created epoch=0x%08x", epoch)

	// Pump outbound frames from this peer's queue into the writer.
	go p.peerWriterPump(stop, out)

	return rt
}

// peerWriterPump drains a peer's outbound KCP queue and writes frames to the
// shared video track. Stops when the channel is closed or transport shuts down.
func (p *streamTransport) peerWriterPump(stop chan struct{}, out chan []byte) {
	for {
		select {
		case <-p.closeCh:
			return
		case <-stop:
			return
		case frame, ok := <-out:
			if !ok {
				return
			}
			p.writeTrackSample(frame)
		}
	}
}

// peerJanitor periodically evicts server-side peer KCP sessions that have gone
// silent. Every client epoch rotation (carrier reconnect / ResetPeer) leaves a
// zombie peer session — its own KCP runtime and writer pump — that nothing
// reclaims, so peer count grows without bound under a reconnect storm. Only
// runs in multi-peer (server) mode; stops when the transport closes.
func (p *streamTransport) peerJanitor() {
	t := time.NewTicker(peerJanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-p.closeCh:
			return
		case <-t.C:
			p.evictIdlePeers()
		}
	}
}

func (p *streamTransport) evictIdlePeers() {
	cutoff := time.Now().UnixNano() - int64(peerIdleTimeout)
	var dead []uint32
	p.peersMu.RLock()
	for epoch, seen := range p.peerSeen {
		if seen.Load() < cutoff {
			dead = append(dead, epoch)
		}
	}
	p.peersMu.RUnlock()
	for _, epoch := range dead {
		p.evictPeer(epoch)
	}
}

// evictPeer tears down a single peer epoch: its KCP runtime, writer pump, and
// bookkeeping. Closing the KCP runtime unblocks any pending WriteTo via the
// kcpConn close signal, so the peer's outbound channel never sees another
// writer and is left for GC rather than closed (avoids a send-on-closed race).
// Safe to call for an unknown epoch (no-op).
func (p *streamTransport) evictPeer(epoch uint32) {
	p.peersMu.Lock()
	rt := p.peers[epoch]
	stop := p.peerStop[epoch]
	delete(p.peers, epoch)
	delete(p.peerOut, epoch)
	delete(p.peerStop, epoch)
	delete(p.peerSeen, epoch)
	p.peersMu.Unlock()
	if rt == nil {
		return
	}
	rt.close()
	if stop != nil {
		close(stop)
	}
	logger.Infof("vp8channel: peer session evicted epoch=0x%08x (idle)", epoch)
}

func formatPeerID(epoch uint32) string {
	return fmt.Sprintf("%08x", epoch)
}

func parsePeerID(peerID string) (uint32, error) {
	v, err := strconv.ParseUint(peerID, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("parse peer ID %q: %w", peerID, err)
	}
	return uint32(v), nil
}

func deliverKCPPayload(rt *kcpRuntime, payload []byte) {
	if rt == nil || len(payload) == 0 {
		return
	}
	splitKCPPayload(payload, rt.deliver)
}

func splitKCPPayload(payload []byte, deliver func([]byte)) {
	if len(payload) < len(kcpBatchMagic) ||
		string(payload[:len(kcpBatchMagic)]) != string(kcpBatchMagic[:]) {
		deliver(payload)
		return
	}

	rest := payload[len(kcpBatchMagic):]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return
		}
		size := int(binary.BigEndian.Uint16(rest[:2]))
		rest = rest[2:]
		if size == 0 || len(rest) < size {
			return
		}
		deliver(rest[:size])
		rest = rest[size:]
	}
}

/*
ПИДОРАС ИЗ ЯНДЕКСА СУКА ПРЕЖДЕ ЧЕМ ФИКСИТЬ ЭТО ЗАДАЙСЯ ВОПРОСОМ:
ПОЧЕМУ ТВОЙ СЕРВЕР ПРИНИМАЕТ ПАКЕТЫ С SEQUENCE NUMBER ИЗ БУДУЩЕГО
БЛЯТЬ ДА ПОТОМУ ЧТО ОН ХУЙНЯ И ТВОЯ МАТЬ СОЛСЕТ МОЙ ХУЙ СУКА Я ЕЕ УБЬЮ БЛЯТЬ
ОЕСЕНЮ СДЕЛАЮ ТЕСТО А ПОТОМ ЭТО ТЕСТО ВЫЕБУ БЛЯТЬ
*/
