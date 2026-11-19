package meshtastic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

const (
	// DefaultTCPAddr is the default Meshtastic TCP StreamAPI endpoint (local meshtasticd).
	DefaultTCPAddr = "127.0.0.1:4403"
	// DefaultTCPPort is the standard Meshtastic TCP StreamAPI port (SERVER_API_DEFAULT_PORT).
	DefaultTCPPort = "4403"

	streamStart1         = 0x94
	streamStart2         = 0xC3
	streamHeaderLen      = 4
	streamMaxPayloadSize = 512 // MAX_TO_FROM_RADIO_SIZE in PhoneAPI.h

	tcpDialTimeout         = 15 * time.Second
	tcpWriteTimeout        = 5 * time.Second
	tcpHandshakeTimeout    = 30 * time.Second
	tcpHeartbeatInterval   = 60 * time.Second
	tcpHeartbeatReadFactor = 3
	// PhoneAPI enforces a 2000ms rate limit between TEXT_MESSAGE_APP packets
	// (PhoneAPI.cpp: TWO_SECONDS_MS). A small safety margin prevents drops from
	// scheduling or clock jitter.
	tcpTextMinInterval = 2100 * time.Millisecond

	specialNonceOnlyConfig uint32 = 69420
	specialNonceOnlyNodes  uint32 = 69421
)

// ExternalNodeState captures live identity and channel metadata learned from
// an external Meshtastic node (meshtasticd or a Wi-Fi/Ethernet hardware node)
// during its TCP StreamAPI handshake.
type ExternalNodeState struct {
	Connected       bool
	ChannelResolved bool
	NodeID          uint32
	ShortName       string
	LongName        string
	ChannelIndex    uint32
	ChannelName     string
	RawPSK          []byte
	UseAEAD         bool
	HopLimit        uint32
	ChannelError    string
}

// NormalizeTCPAddr validates and normalizes a Meshtastic TCP StreamAPI address,
// appending DefaultTCPPort (4403) when no port is specified.
func NormalizeTCPAddr(addr string) (string, error) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return DefaultTCPAddr, nil
	}
	if idx := strings.Index(s, "://"); idx >= 0 {
		scheme := strings.ToLower(s[:idx])
		if scheme != "tcp" {
			return "", fmt.Errorf("meshtastic tcp addr %q: unsupported scheme %q (expected host:port or tcp://host:port)", addr, scheme)
		}
		s = s[idx+3:]
	}
	if strings.ContainsAny(s, " \t\r\n/") {
		return "", fmt.Errorf("meshtastic tcp addr %q: invalid characters in host:port", addr)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// No port supplied: accept bare host, IPv4, IPv6, or [IPv6].
		bare := strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
		if bare == "" {
			return "", fmt.Errorf("meshtastic tcp addr %q: missing host", addr)
		}
		joined := net.JoinHostPort(bare, DefaultTCPPort)
		host, port, err = net.SplitHostPort(joined)
		if err != nil {
			return "", fmt.Errorf("meshtastic tcp addr %q: %w", addr, err)
		}
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("meshtastic tcp addr %q: missing host", addr)
	}
	pnum, perr := strconv.Atoi(port)
	if perr != nil || pnum < 1 || pnum > 65535 {
		return "", fmt.Errorf("meshtastic tcp addr %q: invalid port %q", addr, port)
	}
	return net.JoinHostPort(host, strconv.Itoa(pnum)), nil
}

// TCPTransport connects to an external Meshtastic node (meshtasticd or a real
// Wi-Fi/Ethernet hardware node) over Meshtastic's TCP StreamAPI (port 4403).
type TCPTransport struct {
	addr         string
	channelName  string
	channelIndex *int
	logger       *logging.Logger

	onNodeInfo func(ni *NodeInfo)
	onState    func(st ExternalNodeState)

	// Test hooks (zero values use production defaults).
	dialFn            func(ctx context.Context, addr string) (net.Conn, error)
	heartbeatInterval time.Duration
	handshakeTimeout  time.Duration
	textMinInterval   time.Duration
	disableTextPacing bool

	mu        sync.Mutex
	conn      net.Conn
	connected bool
	state     ExternalNodeState
	readyCh   chan struct{}

	writeMu sync.Mutex

	txPaceMu   sync.Mutex
	lastTextTx time.Time
}

// NewTCPTransport constructs a TCPTransport targeting addr (default 127.0.0.1:4403).
// If channelIndex is non-nil (0..7), that slot is used directly; otherwise
// channelName is matched against the external node's configured channels (or
// the PRIMARY channel is chosen when channelName is empty).
func NewTCPTransport(addr, channelName string, channelIndex *int, logger *logging.Logger) *TCPTransport {
	normAddr, err := NormalizeTCPAddr(addr)
	if err != nil {
		normAddr = strings.TrimSpace(addr)
		if normAddr == "" {
			normAddr = DefaultTCPAddr
		}
	}
	var idxCopy *int
	if channelIndex != nil {
		v := *channelIndex
		idxCopy = &v
	}
	return &TCPTransport{
		addr:         normAddr,
		channelName:  strings.TrimSpace(channelName),
		channelIndex: idxCopy,
		logger:       logger,
		readyCh:      make(chan struct{}),
	}
}

func (t *TCPTransport) Name() string { return "tcp" }

// Addr returns the normalized TCP host:port target.
func (t *TCPTransport) Addr() string { return t.addr }

// Connected reports whether an active post-handshake TCP session is established.
func (t *TCPTransport) Connected() bool {
	t.mu.Lock()
	c := t.connected
	t.mu.Unlock()
	return c
}

// State returns a snapshot of the metadata learned from the external node.
func (t *TCPTransport) State() ExternalNodeState {
	t.mu.Lock()
	st := t.state
	if len(st.RawPSK) > 0 {
		st.RawPSK = append([]byte(nil), st.RawPSK...)
	}
	t.mu.Unlock()
	return st
}

// Ready returns a channel closed after the first successful config handshake.
func (t *TCPTransport) Ready() <-chan struct{} {
	return t.readyCh
}

// Run maintains a reconnecting Meshtastic TCP StreamAPI session until ctx is cancelled.
func (t *TCPTransport) Run(ctx context.Context, onPacket func(*MeshPacket)) error {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		handshakeOK, err := t.runSession(ctx, onPacket)
		if ctx.Err() != nil {
			return nil
		}
		if handshakeOK {
			backoff = 2 * time.Second
		}
		if err != nil && t.logger != nil {
			t.logger.Warnf("meshtastic tcp disconnected (%v); reconnecting in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (t *TCPTransport) runSession(ctx context.Context, onPacket func(*MeshPacket)) (bool, error) {
	dial := dialTCPNode
	if t.dialFn != nil {
		dial = t.dialFn
	}
	conn, err := dial(ctx, t.addr)
	if err != nil {
		return false, err
	}

	defer func() {
		t.mu.Lock()
		t.connected = false
		if t.conn == conn {
			t.conn = nil
		}
		t.state.Connected = false
		st := cloneExternalNodeState(t.state)
		t.mu.Unlock()
		if t.onState != nil {
			t.onState(st)
		}
		_ = conn.Close()
	}()

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	go func() {
		<-sessionCtx.Done()
		// Best-effort ToRadio{Disconnect: true} without blocking Close behind a hung writer.
		if t.writeMu.TryLock() {
			_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Write(frameStreamPacket((&ToRadio{Disconnect: true}).Marshal()))
			t.writeMu.Unlock()
		}
		_ = conn.Close()
	}()

	// 1. Send 32x START2 (0xC3) wake/resync preamble, matching meshtastic-python
	// StreamInterface.connect(), then request full config + channels + NodeDB.
	preamble := bytes.Repeat([]byte{streamStart2}, 32)
	if err := t.writeRaw(conn, preamble); err != nil {
		return false, fmt.Errorf("send stream preamble: %w", err)
	}

	nonce := randomConfigNonce()
	wantCfg := frameStreamPacket((&ToRadio{WantConfigID: nonce}).Marshal())
	if err := t.writeRaw(conn, wantCfg); err != nil {
		return false, fmt.Errorf("send want_config_id: %w", err)
	}

	br := bufio.NewReader(conn)
	hsTimeout := t.handshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = tcpHandshakeTimeout
	}

	var (
		myNodeNum     uint32
		channels      = make(map[int]Channel)
		loraCfg       *LoRaConfig
		pendingNodes  []*NodeInfo
		handshakeDone bool
	)

	// 2. Read FromRadio frames until config_complete_id matches our nonce.
	// Note: PhoneAPI sends STATE_SEND_CHANNELS before STATE_SEND_CONFIG (LoRaConfig),
	// so we buffer channels + NodeInfos and resolve at config_complete_id.
	for !handshakeDone {
		_ = conn.SetReadDeadline(time.Now().Add(hsTimeout))
		raw, rerr := readStreamFrame(br)
		if rerr != nil {
			if sessionCtx.Err() != nil {
				return false, nil
			}
			return false, fmt.Errorf("handshake read: %w", rerr)
		}
		if len(raw) == 0 {
			continue
		}
		fr, uerr := UnmarshalFromRadio(raw)
		if uerr != nil {
			if t.logger != nil {
				t.logger.Debugf("meshtastic tcp malformed FromRadio during handshake: %v", uerr)
			}
			continue
		}
		if fr.MyInfo != nil {
			myNodeNum = fr.MyInfo.MyNodeNum
		}
		if fr.Channel != nil && fr.Channel.Index >= 0 && fr.Channel.Index < 8 {
			channels[int(fr.Channel.Index)] = *fr.Channel
		}
		if fr.Config != nil && fr.Config.LoRa != nil {
			loraCfg = fr.Config.LoRa
		}
		if fr.NodeInfo != nil {
			pendingNodes = append(pendingNodes, fr.NodeInfo)
		}
		if fr.ClientNotification != nil && t.logger != nil {
			t.logger.Warnf("meshtastic tcp device notification: %s (type=%d)", fr.ClientNotification.Message, fr.ClientNotification.Type)
		}
		if fr.HasConfigCompleteID && fr.ConfigCompleteID == nonce {
			handshakeDone = true
		}
	}

	var selfShort, selfLong string
	for _, ni := range pendingNodes {
		if ni != nil && myNodeNum != 0 && ni.Num == myNodeNum && ni.User != nil {
			selfShort = ni.User.ShortName
			selfLong = ni.User.LongName
		}
	}

	resolved := resolveExternalChannel(channels, loraCfg, t.channelName, t.channelIndex)
	hopLimit := uint32(0)
	if loraCfg != nil && loraCfg.HopLimit > 0 && loraCfg.HopLimit <= 7 {
		hopLimit = loraCfg.HopLimit
	}

	st := ExternalNodeState{
		Connected:       true,
		ChannelResolved: resolved.ok,
		NodeID:          myNodeNum,
		ShortName:       selfShort,
		LongName:        selfLong,
		ChannelIndex:    resolved.index,
		ChannelName:     resolved.name,
		RawPSK:          resolved.rawPSK,
		UseAEAD:         resolved.useAEAD,
		HopLimit:        hopLimit,
		ChannelError:    resolved.errMsg,
	}

	t.mu.Lock()
	t.conn = conn
	t.connected = true
	t.state = cloneExternalNodeState(st)
	t.mu.Unlock()

	if t.onState != nil {
		t.onState(cloneExternalNodeState(st))
	}

	peerCount := 0
	for _, ni := range pendingNodes {
		if ni == nil || ni.Num == 0 || ni.Num == myNodeNum {
			continue
		}
		peerCount++
		if t.onNodeInfo != nil {
			t.onNodeInfo(ni)
		}
	}

	// Close readyCh only after onState and NodeDB seeding have completed so any
	// waiter on Ready() observes the resolved channel, node ID, and peer names.
	t.mu.Lock()
	select {
	case <-t.readyCh:
	default:
		close(t.readyCh)
	}
	t.mu.Unlock()

	if t.logger != nil {
		if resolved.ok {
			t.logger.Infof("meshtastic tcp connected to %s (node=%s %q/%q, channel=%d:#%s, nodes=%d)",
				t.addr, FormatNodeBang(myNodeNum), selfShort, selfLong, resolved.index, resolved.name, peerCount)
		} else {
			t.logger.Errorf("meshtastic tcp connected to %s (node=%s) but %s; refusing to transmit/receive until channel matches or meshtastic.tcp.channel_index is set",
				t.addr, FormatNodeBang(myNodeNum), resolved.errMsg)
		}
	}

	// 3. Keepalive heartbeat loop (prevents ServerAPI's 15-minute TCP_IDLE_TIMEOUT_MS
	// and probes peer liveness on firmware >= 2.6/2.7 that replies with QueueStatus).
	hbInterval := t.heartbeatInterval
	if hbInterval <= 0 {
		hbInterval = tcpHeartbeatInterval
	}
	var heartbeatSent atomic.Bool
	go func() {
		ticker := time.NewTicker(hbInterval)
		defer ticker.Stop()
		hbFrame := frameStreamPacket((&ToRadio{Heartbeat: &Heartbeat{}}).Marshal())
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				if err := t.writeRaw(conn, hbFrame); err != nil {
					cancelSession()
					return
				}
				heartbeatSent.Store(true)
			}
		}
	}()

	// 4. Steady-state FromRadio read loop.
	peerRepliesToHeartbeat := false
	for {
		if peerRepliesToHeartbeat {
			_ = conn.SetReadDeadline(time.Now().Add(hbInterval * tcpHeartbeatReadFactor))
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		raw, rerr := readStreamFrame(br)
		if rerr != nil {
			if sessionCtx.Err() != nil {
				return true, nil
			}
			return true, rerr
		}
		if len(raw) == 0 {
			continue
		}
		fr, uerr := UnmarshalFromRadio(raw)
		if uerr != nil {
			if t.logger != nil {
				t.logger.Debugf("meshtastic tcp malformed FromRadio: %v", uerr)
			}
			continue
		}

		if fr.Rebooted {
			if t.logger != nil {
				t.logger.Warnf("meshtastic tcp remote node %s rebooted; reconnecting", FormatNodeBang(myNodeNum))
			}
			return true, errors.New("remote node rebooted")
		}

		if fr.MyInfo != nil && fr.MyInfo.MyNodeNum != 0 && fr.MyInfo.MyNodeNum != myNodeNum {
			myNodeNum = fr.MyInfo.MyNodeNum
			t.mu.Lock()
			t.state.NodeID = myNodeNum
			updated := cloneExternalNodeState(t.state)
			t.mu.Unlock()
			if t.onState != nil {
				t.onState(updated)
			}
			if t.logger != nil {
				t.logger.Infof("meshtastic tcp external node ID updated to %s", FormatNodeBang(myNodeNum))
			}
		}

		if fr.NodeInfo != nil {
			if myNodeNum != 0 && fr.NodeInfo.Num == myNodeNum {
				if fr.NodeInfo.User != nil {
					t.mu.Lock()
					if fr.NodeInfo.User.ShortName != "" {
						t.state.ShortName = fr.NodeInfo.User.ShortName
					}
					if fr.NodeInfo.User.LongName != "" {
						t.state.LongName = fr.NodeInfo.User.LongName
					}
					updated := cloneExternalNodeState(t.state)
					t.mu.Unlock()
					if t.onState != nil {
						t.onState(updated)
					}
				}
			} else if t.onNodeInfo != nil {
				t.onNodeInfo(fr.NodeInfo)
			}
		}

		if fr.QueueStatus != nil {
			// Firmware >= 2.6/2.7 replies to ToRadio.Heartbeat with QueueStatus{MeshPacketID: 0}.
			// Only arm the strict heartbeat read deadline once that behavior is observed so
			// older firmware (which emits QueueStatus only for sends with MeshPacketID != 0)
			// does not spuriously disconnect on quiet meshes.
			if fr.QueueStatus.MeshPacketID == 0 && heartbeatSent.Load() {
				peerRepliesToHeartbeat = true
			}
			if fr.QueueStatus.Res != 0 && t.logger != nil {
				t.logger.Warnf("meshtastic tcp queue status error: pkt=0x%08x res=%d free=%d/%d",
					fr.QueueStatus.MeshPacketID, fr.QueueStatus.Res, fr.QueueStatus.Free, fr.QueueStatus.Maxlen)
			}
		}

		if fr.ClientNotification != nil && t.logger != nil {
			t.logger.Warnf("meshtastic tcp device notification: %s (reply_id=0x%08x type=%d)",
				fr.ClientNotification.Message, fr.ClientNotification.ReplyID, fr.ClientNotification.Type)
		}

		if fr.Packet != nil {
			if fr.Packet.Decoded != nil && fr.Packet.Decoded.Portnum == PortNumRoutingApp &&
				myNodeNum != 0 && (fr.Packet.To == myNodeNum || fr.Packet.From == myNodeNum) && t.logger != nil {
				if rt, rerr := UnmarshalRouting(fr.Packet.Decoded.Payload); rerr == nil && rt.ErrorReason != 0 {
					t.logger.Warnf("meshtastic tcp routing error for pkt=0x%08x: error_reason=%d",
						fr.Packet.Decoded.RequestID, rt.ErrorReason)
				}
			}
			if onPacket != nil {
				onPacket(fr.Packet)
			}
		}
	}
}

// Send wraps a decoded MeshPacket into ToRadio and writes it framed over TCP
// to the external Meshtastic node on the resolved local channel index.
func (t *TCPTransport) Send(ctx context.Context, pkt *MeshPacket) error {
	if pkt == nil {
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if pkt.Decoded == nil {
		return errors.New("meshtastic tcp requires decoded Data payload")
	}

	// Fast-fail before waiting on TX pacing when not connected or channel unresolved.
	t.mu.Lock()
	connected := t.connected
	conn := t.conn
	chResolved := t.state.ChannelResolved
	chErr := t.state.ChannelError
	t.mu.Unlock()

	if !connected || conn == nil {
		return fmt.Errorf("meshtastic tcp not connected")
	}
	if !chResolved {
		if chErr != "" {
			return fmt.Errorf("meshtastic tcp channel not resolved: %s", chErr)
		}
		return fmt.Errorf("meshtastic tcp channel not resolved")
	}

	isText := pkt.Decoded.Portnum == PortNumTextMessageApp
	t.txPaceMu.Lock()
	defer t.txPaceMu.Unlock()

	if isText && !t.disableTextPacing {
		minInt := t.textMinInterval
		if minInt <= 0 {
			minInt = tcpTextMinInterval
		}
		if !t.lastTextTx.IsZero() {
			if wait := minInt - time.Since(t.lastTextTx); wait > 0 {
				if ctx != nil {
					timer := time.NewTimer(wait)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
					}
				} else {
					time.Sleep(wait)
				}
			}
		}
	}

	// Re-read active connection and resolved channel state after any pacing wait.
	t.mu.Lock()
	conn = t.conn
	connected = t.connected
	chResolved = t.state.ChannelResolved
	chIndex := t.state.ChannelIndex
	nodeHopLimit := t.state.HopLimit
	chErr = t.state.ChannelError
	t.mu.Unlock()

	if !connected || conn == nil {
		return fmt.Errorf("meshtastic tcp not connected")
	}
	if !chResolved {
		if chErr != "" {
			return fmt.Errorf("meshtastic tcp channel not resolved: %s", chErr)
		}
		return fmt.Errorf("meshtastic tcp channel not resolved")
	}

	// Never mutate the caller's *MeshPacket (shared read-only across transport workers).
	out := *pkt
	out.From = 0 // MeshService::handleToRadio overwrites from with the node's own ID.
	out.Channel = chIndex
	out.Encrypted = nil
	if out.To == BroadcastAddr {
		out.WantAck = false
	}
	if out.HopLimit == 0 {
		if nodeHopLimit > 0 && nodeHopLimit <= 7 {
			out.HopLimit = nodeHopLimit
		} else {
			out.HopLimit = 3
		}
	}
	out.HopStart = 0 // Router::send stamps hop_start = hop_limit for local sends.

	raw := (&ToRadio{Packet: &out}).Marshal()
	if len(raw) > streamMaxPayloadSize {
		return fmt.Errorf("meshtastic tcp ToRadio too large (%d > %d)", len(raw), streamMaxPayloadSize)
	}
	frame := frameStreamPacket(raw)
	if err := t.writeRaw(conn, frame); err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.connected = false
			t.state.Connected = false
		}
		t.mu.Unlock()
		_ = conn.Close()
		return fmt.Errorf("meshtastic tcp write: %w", err)
	}
	if isText {
		t.lastTextTx = time.Now()
	}
	if t.logger != nil {
		t.logger.Debugf("meshtastic tcp sent id=0x%08x ch=%d (%d B)", out.ID, out.Channel, len(frame))
	}
	return nil
}

func (t *TCPTransport) writeRaw(conn net.Conn, data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
	_, err := conn.Write(data)
	return err
}

func dialTCPNode(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   tcpDialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

func frameStreamPacket(payload []byte) []byte {
	n := len(payload)
	out := make([]byte, streamHeaderLen+n)
	out[0] = streamStart1
	out[1] = streamStart2
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[streamHeaderLen:], payload)
	return out
}

// readStreamFrame scans for the 0x94 0xC3 <MSB> <LSB> StreamAPI header (ignoring
// any interleaved ASCII debug logs and resyncing on stray markers or oversized
// lengths) and returns the protobuf payload bytes.
func readStreamFrame(r *bufio.Reader) ([]byte, error) {
	const (
		stateStart1 = 0
		stateStart2 = 1
		stateLenHi  = 2
		stateLenLo  = 3
	)
	state := stateStart1
	var lenHi byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch state {
		case stateStart1:
			if b == streamStart1 {
				state = stateStart2
			}
		case stateStart2:
			switch b {
			case streamStart2:
				state = stateLenHi
			case streamStart1:
				// Stay in stateStart2 to handle 0x94 0x94 0xC3.
			default:
				state = stateStart1
			}
		case stateLenHi:
			lenHi = b
			state = stateLenLo
		case stateLenLo:
			n := (int(lenHi) << 8) | int(b)
			if n <= streamMaxPayloadSize {
				payload := make([]byte, n)
				if _, err := io.ReadFull(r, payload); err != nil {
					return nil, err
				}
				return payload, nil
			}
			// Oversized length (>512): treat as false sync and rescan from lenHi/b.
			switch {
			case lenHi == streamStart1 && b == streamStart2:
				state = stateLenHi
			case b == streamStart1:
				state = stateStart2
			default:
				state = stateStart1
			}
		}
	}
}

func randomConfigNonce() uint32 {
	for {
		var buf [4]byte
		var v uint32
		if _, err := rand.Read(buf[:]); err == nil {
			v = binary.LittleEndian.Uint32(buf[:])
		} else {
			v = uint32(time.Now().UnixNano())
		}
		if v != 0 && v != specialNonceOnlyConfig && v != specialNonceOnlyNodes {
			return v
		}
	}
}

type resolvedChannel struct {
	ok      bool
	index   uint32
	name    string
	rawPSK  []byte
	useAEAD bool
	errMsg  string
}

func resolveExternalChannel(channels map[int]Channel, loraCfg *LoRaConfig, wantName string, wantIndex *int) resolvedChannel {
	primaryIdx := -1
	for idx := 0; idx < 8; idx++ {
		if ch, ok := channels[idx]; ok && ch.Role == ChannelRolePrimary {
			primaryIdx = idx
			break
		}
	}
	if primaryIdx < 0 {
		if ch, ok := channels[0]; ok && ch.Role != ChannelRoleDisabled {
			primaryIdx = 0
		}
	}

	effectiveName := func(ch Channel) string {
		if ch.Settings.Name != "" {
			return ch.Settings.Name
		}
		if loraCfg != nil {
			return ModemPresetDisplayName(loraCfg.ModemPreset, loraCfg.UsePreset)
		}
		return "LongFast"
	}

	effectivePSK := func(ch Channel) []byte {
		if len(ch.Settings.PSK) > 0 {
			if len(ch.Settings.PSK) == 1 && ch.Settings.PSK[0] == 0 {
				return nil
			}
			return append([]byte(nil), ch.Settings.PSK...)
		}
		// Match Channels::getKey: secondary channels with empty PSK inherit the primary PSK.
		if ch.Role == ChannelRoleSecondary && primaryIdx >= 0 && int(ch.Index) != primaryIdx {
			if prim, ok := channels[primaryIdx]; ok && len(prim.Settings.PSK) > 0 {
				if len(prim.Settings.PSK) == 1 && prim.Settings.PSK[0] == 0 {
					return nil
				}
				return append([]byte(nil), prim.Settings.PSK...)
			}
		}
		return nil
	}

	// Case 1: Explicit channel_index configured.
	if wantIndex != nil {
		idx := *wantIndex
		ch, ok := channels[idx]
		if !ok {
			return resolvedChannel{
				ok:     false,
				errMsg: fmt.Sprintf("channel index %d was not reported by external node", idx),
			}
		}
		if ch.Role == ChannelRoleDisabled {
			return resolvedChannel{
				ok:     false,
				errMsg: fmt.Sprintf("channel index %d is DISABLED on external node", idx),
			}
		}
		return resolvedChannel{
			ok:      true,
			index:   uint32(idx),
			name:    effectiveName(ch),
			rawPSK:  effectivePSK(ch),
			useAEAD: ch.Settings.UseAEAD,
		}
	}

	// Collect enabled channels in index order for deterministic matching and error reporting.
	type chEntry struct {
		idx  int
		ch   Channel
		name string
	}
	var enabled []chEntry
	for idx := 0; idx < 8; idx++ {
		if ch, ok := channels[idx]; ok && ch.Role != ChannelRoleDisabled {
			enabled = append(enabled, chEntry{idx: idx, ch: ch, name: effectiveName(ch)})
		}
	}

	// Case 2: Match by channel_name.
	wantName = strings.TrimSpace(wantName)
	if wantName != "" {
		// Pass 1: exact name match (plus legacy "Default" alias for unnamed primary).
		for _, e := range enabled {
			if e.name == wantName || (wantName == "Default" && e.ch.Role == ChannelRolePrimary && e.ch.Settings.Name == "") {
				return resolvedChannel{
					ok:      true,
					index:   uint32(e.idx),
					name:    e.name,
					rawPSK:  effectivePSK(e.ch),
					useAEAD: e.ch.Settings.UseAEAD,
				}
			}
		}
		// Pass 2: case-insensitive match (plus LongModerate <-> LongMod convenience).
		for _, e := range enabled {
			if strings.EqualFold(e.name, wantName) ||
				(strings.EqualFold(wantName, "LongModerate") && strings.EqualFold(e.name, "LongMod")) {
				return resolvedChannel{
					ok:      true,
					index:   uint32(e.idx),
					name:    e.name,
					rawPSK:  effectivePSK(e.ch),
					useAEAD: e.ch.Settings.UseAEAD,
				}
			}
		}
		avail := "none"
		if len(enabled) > 0 {
			parts := make([]string, len(enabled))
			for i, e := range enabled {
				parts[i] = fmt.Sprintf("%d:#%s", e.idx, e.name)
			}
			sort.Strings(parts)
			avail = strings.Join(parts, ", ")
		}
		return resolvedChannel{
			ok:     false,
			errMsg: fmt.Sprintf("channel %q not found on external node (available: [%s])", wantName, avail),
		}
	}

	// Case 3: Neither channel_index nor channel_name set -> use PRIMARY channel.
	if primaryIdx >= 0 {
		ch := channels[primaryIdx]
		return resolvedChannel{
			ok:      true,
			index:   uint32(primaryIdx),
			name:    effectiveName(ch),
			rawPSK:  effectivePSK(ch),
			useAEAD: ch.Settings.UseAEAD,
		}
	}
	return resolvedChannel{
		ok:     false,
		errMsg: "no enabled PRIMARY channel reported by external node",
	}
}

func cloneExternalNodeState(st ExternalNodeState) ExternalNodeState {
	cp := st
	if len(st.RawPSK) > 0 {
		cp.RawPSK = append([]byte(nil), st.RawPSK...)
	}
	return cp
}
