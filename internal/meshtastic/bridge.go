package meshtastic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

const (
	// ModeInternal uses fwdsvc's built-in virtual Meshtastic node over UDP multicast and/or MQTT.
	ModeInternal = "internal"
	// ModeExternal connects via TCP StreamAPI to an external Meshtastic node (meshtasticd or Wi-Fi/Ethernet radio).
	ModeExternal = "external"

	meshDedupWindow      = time.Hour
	meshDedupMaxEntries  = 10000
	meshTxQueueCap       = 256
	meshNodeFlushPeriod  = 30 * time.Second
	nodeInfoReplyMinWait = 15 * time.Second
)

// Transport abstracts UDP multicast, MQTT, TCP StreamAPI, and test doubles.
type Transport interface {
	Name() string
	Run(ctx context.Context, onPacket func(pkt *MeshPacket)) error
	Send(ctx context.Context, pkt *MeshPacket) error
}

// InboundMessage is a verified, decrypted Meshtastic TEXT_MESSAGE_APP packet.
type InboundMessage struct {
	From     uint32
	PacketID uint32
	Text     string
	ReplyID  uint32
	Emoji    uint32
}

// BridgeConfig configures a Bridge instance.
type BridgeConfig struct {
	Mode             string // "internal" (default) or "external"
	ChannelName      string
	RawPSK           []byte
	ExpandedKey      []byte
	BridgeNodeID     uint32
	ShortName        string
	LongName         string
	NodeInfoInterval time.Duration
	HopLimit         uint32
	OKToMQTT         bool
	LongNameFormat   bool
	LongMessageMode  string
	MaxChunks        int
	ChunkDelay       time.Duration
	NodeDBPath       string

	UDPEnabled bool
	UDPAddr    string
	UDPIface   string

	MQTTEnabled  bool
	MQTTBroker   string
	MQTTUsername string
	MQTTPassword string
	MQTTRoot     string

	TCPAddr         string
	TCPChannelIndex *int
}

// DeriveNodeID derives a deterministic non-reserved 32-bit Meshtastic node ID
// from a 16-byte Reticulum identity/destination hash.
func DeriveNodeID(hash []byte) uint32 {
	var id uint32
	if len(hash) >= 4 {
		id = binary.BigEndian.Uint32(hash[len(hash)-4:])
	}
	if id == 0 || id == BroadcastAddr {
		return 0x524e5301 // "RNS\x01"
	}
	return id
}

// Bridge connects fwdsvc to a Meshtastic channel either directly (internal mode
// over UDP multicast and/or MQTT) or via an external Meshtastic node (external
// mode over TCP StreamAPI).
type Bridge struct {
	cfg         BridgeConfig
	channelHash uint8
	nodedb      *NodeDB
	transports  []Transport
	udp         *UDPTransport
	mqtt        *MQTTTransport
	tcp         *TCPTransport
	onMessage   func(InboundMessage)
	logger      *logging.Logger

	extMu    sync.RWMutex
	extState ExternalNodeState

	nextPktID atomic.Uint32
	txCh      chan *MeshPacket

	dedupMu sync.Mutex
	dedup   map[uint64]time.Time

	nodeInfoReplyMu sync.Mutex
	lastNodeReply   time.Time

	now func() time.Time
}

// NewBridge constructs a Bridge and loads its persisted NodeDB. Call Run to
// start transports, outbound pacing, and periodic NODEINFO announcements.
func NewBridge(cfg BridgeConfig, onMessage func(InboundMessage), logger *logging.Logger) (*Bridge, error) {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = ModeInternal
	}
	if cfg.Mode != ModeInternal && cfg.Mode != ModeExternal {
		return nil, fmt.Errorf("meshtastic: invalid mode %q (want %q or %q)", cfg.Mode, ModeInternal, ModeExternal)
	}
	if cfg.Mode == ModeInternal {
		if cfg.BridgeNodeID == 0 || cfg.BridgeNodeID == BroadcastAddr {
			return nil, fmt.Errorf("meshtastic: invalid bridge node id 0x%08x", cfg.BridgeNodeID)
		}
		if strings.TrimSpace(cfg.ChannelName) == "" {
			return nil, fmt.Errorf("meshtastic: channel_name is required")
		}
	}
	if cfg.HopLimit == 0 {
		cfg.HopLimit = 3
	}
	if cfg.MaxChunks <= 0 {
		cfg.MaxChunks = 3
	}
	if cfg.ShortName == "" {
		cfg.ShortName = "RNS"
	}
	if cfg.LongName == "" {
		cfg.LongName = "Reticulum Bridge"
	}
	if cfg.TCPChannelIndex != nil {
		idx := *cfg.TCPChannelIndex
		if idx < 0 || idx > 7 {
			return nil, fmt.Errorf("meshtastic: tcp channel_index must be 0..7 (got %d)", idx)
		}
		idxCopy := idx
		cfg.TCPChannelIndex = &idxCopy
	}

	db, err := NewNodeDB(cfg.NodeDBPath)
	if err != nil {
		return nil, fmt.Errorf("load mesh nodedb: %w", err)
	}

	b := &Bridge{
		cfg:       cfg,
		nodedb:    db,
		onMessage: onMessage,
		logger:    logger,
		txCh:      make(chan *MeshPacket, meshTxQueueCap),
		dedup:     make(map[uint64]time.Time),
		now:       time.Now,
	}
	if cfg.Mode == ModeInternal {
		b.channelHash = ChannelHash(cfg.ChannelName, cfg.ExpandedKey)
	}

	var seed [4]byte
	if _, rerr := rand.Read(seed[:]); rerr == nil {
		v := binary.LittleEndian.Uint32(seed[:])
		if v == 0 {
			v = 1
		}
		b.nextPktID.Store(v)
	} else {
		b.nextPktID.Store(uint32(time.Now().UnixNano()))
	}

	if cfg.Mode == ModeExternal {
		t := NewTCPTransport(cfg.TCPAddr, cfg.ChannelName, cfg.TCPChannelIndex, logger)
		t.onNodeInfo = b.handleExternalNodeInfo
		t.onState = b.handleExternalState
		b.tcp = t
		b.transports = append(b.transports, t)
	} else {
		if cfg.UDPEnabled {
			u := NewUDPTransport(cfg.UDPAddr, cfg.UDPIface, logger)
			b.udp = u
			b.transports = append(b.transports, u)
		}
		if cfg.MQTTEnabled {
			m := NewMQTTTransport(
				cfg.MQTTBroker,
				cfg.MQTTUsername,
				cfg.MQTTPassword,
				cfg.MQTTRoot,
				cfg.ChannelName,
				FormatNodeHex(cfg.BridgeNodeID),
				logger,
			)
			b.mqtt = m
			b.transports = append(b.transports, m)
		}
	}

	return b, nil
}

// AddTransport registers an additional Transport (typically used by tests)
// before Run is started.
func (b *Bridge) AddTransport(t Transport) {
	if t != nil {
		b.transports = append(b.transports, t)
	}
}

// SetTransports replaces the configured transports (typically used by tests)
// before Run is started.
func (b *Bridge) SetTransports(transports ...Transport) {
	b.transports = append([]Transport(nil), transports...)
}

// Mode returns the configured bridge mode ("internal" or "external").
func (b *Bridge) Mode() string { return b.cfg.Mode }

func (b *Bridge) isExternal() bool { return b.cfg.Mode == ModeExternal }

// TCPTransport returns the external-mode TCPTransport, or nil in internal mode.
func (b *Bridge) TCPTransport() *TCPTransport { return b.tcp }

// NodeDB returns the bridge's node database (used by /ban, /unban, /mesh).
func (b *Bridge) NodeDB() *NodeDB { return b.nodedb }

// ChannelHash returns the 8-bit Meshtastic channel hash for the bridged channel.
func (b *Bridge) ChannelHash() uint8 {
	if b.isExternal() {
		st := b.externalState()
		if st.ChannelResolved {
			if h, ok := externalChannelHash(st); ok {
				return h
			}
		}
		return 0
	}
	return b.channelHash
}

// ChannelName returns the active bridged channel name (learned from the external
// node once connected in external mode, or the configured channel_name).
func (b *Bridge) ChannelName() string {
	if b.isExternal() {
		st := b.externalState()
		if st.ChannelName != "" {
			return st.ChannelName
		}
	}
	return b.cfg.ChannelName
}

// BridgeNodeID returns the virtual node ID (internal mode) or the connected
// external node's ID (external mode; 0 until handshake completes).
func (b *Bridge) BridgeNodeID() uint32 {
	if b.isExternal() {
		b.extMu.RLock()
		id := b.extState.NodeID
		b.extMu.RUnlock()
		return id
	}
	return b.cfg.BridgeNodeID
}

// StartupSummary returns a single-line startup log summary for Service.Run.
func (b *Bridge) StartupSummary() string {
	if b.isExternal() {
		addr := DefaultTCPAddr
		if b.tcp != nil {
			addr = b.tcp.Addr()
		} else if b.cfg.TCPAddr != "" {
			addr = b.cfg.TCPAddr
		}
		switch {
		case b.cfg.TCPChannelIndex != nil:
			return fmt.Sprintf("mode=external tcp=%s channel_index=%d", addr, *b.cfg.TCPChannelIndex)
		case b.cfg.ChannelName != "":
			return fmt.Sprintf("mode=external tcp=%s channel=#%s", addr, b.cfg.ChannelName)
		default:
			return fmt.Sprintf("mode=external tcp=%s channel=primary", addr)
		}
	}
	return fmt.Sprintf("mode=internal #%s (hash=0x%02x node=%s)",
		b.cfg.ChannelName, b.channelHash, FormatNodeBang(b.cfg.BridgeNodeID))
}

func (b *Bridge) externalState() ExternalNodeState {
	b.extMu.RLock()
	st := cloneExternalNodeState(b.extState)
	b.extMu.RUnlock()
	return st
}

func (b *Bridge) handleExternalState(st ExternalNodeState) {
	b.extMu.Lock()
	b.extState = cloneExternalNodeState(st)
	b.extMu.Unlock()
}

func (b *Bridge) handleExternalNodeInfo(ni *NodeInfo) {
	if ni == nil || ni.Num == 0 || ni.Num == BroadcastAddr || ni.User == nil {
		return
	}
	if !isValidUserStrings(ni.User) {
		return
	}
	if myID := b.BridgeNodeID(); myID != 0 && ni.Num == myID {
		return
	}
	var seenAt time.Time
	// Match PhoneAPI.cpp MIN_PLAUSIBLE_EPOCH (2020-01-01): ignore uptime-only counters.
	if ni.LastHeard >= 1577836800 {
		seenAt = time.Unix(int64(ni.LastHeard), 0)
	}
	b.nodedb.UpdateUser(ni.Num, ni.User.ShortName, ni.User.LongName, seenAt)
}

func externalChannelHash(st ExternalNodeState) (uint8, bool) {
	if !st.ChannelResolved || st.ChannelName == "" {
		return 0, false
	}
	exp, err := ExpandPSK(st.RawPSK)
	if err != nil {
		return 0, false
	}
	h := ChannelHash(st.ChannelName, exp)
	if st.UseAEAD {
		h ^= 0xAE
	}
	return h, true
}

// FormatSenderLabel formats a Meshtastic sender node ID according to config.
func (b *Bridge) FormatSenderLabel(nodeID uint32) string {
	return b.nodedb.FormatSenderLabel(nodeID, b.cfg.LongNameFormat)
}

// Run starts all configured transports, outbound paced transmitter, periodic
// NODEINFO broadcasts, and NodeDB persistence flushing until ctx is cancelled.
func (b *Bridge) Run(ctx context.Context) {
	var wg sync.WaitGroup

	txQueues := make([]transportTxQueue, 0, len(b.transports))
	for _, tr := range b.transports {
		t := tr
		if t == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := t.Run(ctx, b.handleInboundPacket); err != nil && ctx.Err() == nil && b.logger != nil {
				b.logger.Errorf("meshtastic %s stopped: %v", t.Name(), err)
			}
		}()

		txq := make(chan *MeshPacket, meshTxQueueCap)
		txQueues = append(txQueues, transportTxQueue{name: t.Name(), ch: txq})
		wg.Add(1)
		go b.runTransportTxWorker(ctx, &wg, t, txq)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		b.runTxLoop(ctx, txQueues)
	}()

	if !b.isExternal() && b.cfg.NodeInfoInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.runNodeInfoLoop(ctx)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(meshNodeFlushPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				if err := b.nodedb.Flush(); err != nil && b.logger != nil {
					b.logger.Errorf("mesh nodedb flush on shutdown: %v", err)
				}
				return
			case <-ticker.C:
				if err := b.nodedb.Flush(); err != nil && b.logger != nil {
					b.logger.Errorf("mesh nodedb flush: %v", err)
				}
			}
		}
	}()

	wg.Wait()
}

type transportTxQueue struct {
	name string
	ch   chan *MeshPacket
}

func (b *Bridge) runTransportTxWorker(ctx context.Context, wg *sync.WaitGroup, tr Transport, txq <-chan *MeshPacket) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-txq:
			if pkt == nil {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			if err := tr.Send(ctx, pkt); err != nil && ctx.Err() == nil && b.logger != nil {
				b.logger.Warnf("meshtastic %s send id=0x%08x failed: %v", tr.Name(), pkt.ID, err)
			}
		}
	}
}

func (b *Bridge) runTxLoop(ctx context.Context, txQueues []transportTxQueue) {
	var lastSend time.Time
	for {
		var pkt *MeshPacket
		select {
		case <-ctx.Done():
			return
		case pkt = <-b.txCh:
		}
		if pkt == nil {
			continue
		}
		if b.cfg.ChunkDelay > 0 && !lastSend.IsZero() {
			wait := b.cfg.ChunkDelay - b.now().Sub(lastSend)
			if wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		// Dispatch independently per transport so a slow or stalled MQTT write
		// never delays local UDP multicast (or vice versa).
		for _, q := range txQueues {
			select {
			case q.ch <- pkt:
			default:
				if b.logger != nil {
					b.logger.Warnf("meshtastic %s outbound queue full (%d); dropping packet 0x%08x", q.name, cap(q.ch), pkt.ID)
				}
			}
		}
		lastSend = b.now()
	}
}

func (b *Bridge) runNodeInfoLoop(ctx context.Context) {
	// Wait briefly so transports finish opening before initial NODEINFO announce.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}
	b.SendNodeInfo(BroadcastAddr, 0)

	ticker := time.NewTicker(b.cfg.NodeInfoInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.SendNodeInfo(BroadcastAddr, 0)
		}
	}
}

// SendText chunks or truncates text per policy, constructs MeshPackets with
// pre-assigned packet IDs, queues them for paced transmission, and returns the
// assigned packet IDs immediately (for idmap registration).
func (b *Bridge) SendText(text string, replyToPacketID uint32) []uint32 {
	chunks := SplitMessage(text, b.cfg.LongMessageMode, b.cfg.MaxChunks, MaxMeshPayloadBytes)
	if len(chunks) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(chunks))
	for i, chunk := range chunks {
		replyID := uint32(0)
		if i == 0 {
			replyID = replyToPacketID
		}
		d := &Data{
			Portnum: PortNumTextMessageApp,
			Payload: []byte(chunk),
			ReplyID: replyID,
		}
		if !b.isExternal() {
			d.Bitfield = b.txBitfield()
			d.HasBitfield = true
		}
		pkt, err := b.buildDataPacket(BroadcastAddr, d)
		if err != nil {
			if b.logger != nil {
				b.logger.Errorf("meshtastic build text packet: %v", err)
			}
			continue
		}
		if b.enqueueTx(pkt) {
			ids = append(ids, pkt.ID)
		}
	}
	return ids
}

// SendReaction sends a Meshtastic tap-back reaction (Emoji=1, ReplyID != 0).
func (b *Bridge) SendReaction(emoji string, replyToPacketID uint32) uint32 {
	if emoji == "" || replyToPacketID == 0 {
		return 0
	}
	d := &Data{
		Portnum: PortNumTextMessageApp,
		Payload: []byte(emoji),
		ReplyID: replyToPacketID,
		Emoji:   1,
	}
	if !b.isExternal() {
		d.Bitfield = b.txBitfield()
		d.HasBitfield = true
	}
	pkt, err := b.buildDataPacket(BroadcastAddr, d)
	if err != nil {
		if b.logger != nil {
			b.logger.Errorf("meshtastic build reaction packet: %v", err)
		}
		return 0
	}
	if !b.enqueueTx(pkt) {
		return 0
	}
	return pkt.ID
}

// SendNodeInfo queues a NODEINFO_APP packet describing the virtual bridge node.
// In external mode this is a no-op because the external Meshtastic node manages
// its own NodeInfo broadcasts.
func (b *Bridge) SendNodeInfo(toNode uint32, requestID uint32) uint32 {
	if b.isExternal() {
		return 0
	}
	u := &User{
		ID:        FormatNodeBang(b.cfg.BridgeNodeID),
		LongName:  truncateUTF8(b.cfg.LongName, 39, false),
		ShortName: truncateUTF8(b.cfg.ShortName, 4, false),
		HwModel:   HwModelPrivate,
	}
	pkt, err := b.buildDataPacket(toNode, &Data{
		Portnum:     PortNumNodeInfoApp,
		Payload:     u.Marshal(),
		RequestID:   requestID,
		Bitfield:    b.txBitfield(),
		HasBitfield: true,
	})
	if err != nil {
		if b.logger != nil {
			b.logger.Errorf("meshtastic build nodeinfo packet: %v", err)
		}
		return 0
	}
	if !b.enqueueTx(pkt) {
		return 0
	}
	return pkt.ID
}

func (b *Bridge) txBitfield() uint32 {
	if b.cfg.OKToMQTT {
		return BitfieldOKToMQTT
	}
	return 0
}

func (b *Bridge) allocPacketID() uint32 {
	for {
		v := b.nextPktID.Add(1)
		if v != 0 {
			return v
		}
	}
}

func (b *Bridge) buildDataPacket(toNode uint32, data *Data) (*MeshPacket, error) {
	pktID := b.allocPacketID()
	if b.isExternal() {
		// External Meshtastic node encrypts, signs, stamps From, and maps Channel index.
		return &MeshPacket{
			To:       toNode,
			ID:       pktID,
			HopLimit: b.cfg.HopLimit,
			Decoded:  data,
		}, nil
	}
	rawData := data.Marshal()
	pkt := &MeshPacket{
		From:     b.cfg.BridgeNodeID,
		To:       toNode,
		Channel:  uint32(b.channelHash),
		ID:       pktID,
		HopLimit: b.cfg.HopLimit,
		HopStart: b.cfg.HopLimit,
	}
	if len(b.cfg.ExpandedKey) == 0 {
		pkt.Decoded = data
		return pkt, nil
	}
	enc, err := CryptPacket(rawData, pktID, b.cfg.BridgeNodeID, b.cfg.ExpandedKey)
	if err != nil {
		return nil, err
	}
	pkt.Encrypted = enc
	return pkt, nil
}

func (b *Bridge) enqueueTx(pkt *MeshPacket) bool {
	select {
	case b.txCh <- pkt:
		return true
	default:
		if b.logger != nil {
			b.logger.Warnf("meshtastic outbound queue full (%d); dropping packet 0x%08x", meshTxQueueCap, pkt.ID)
		}
		return false
	}
}

// handleInboundPacket processes a packet received from UDP/MQTT (internal mode)
// or TCP StreamAPI (external mode). It enforces strict endpoint semantics
// (dedup, ignore self, channel match, decrypt/decoded check, ban check) and
// never cross-relays between transports.
func (b *Bridge) handleInboundPacket(pkt *MeshPacket) {
	if b.isExternal() {
		b.handleExternalInboundPacket(pkt)
		return
	}
	if pkt == nil || pkt.From == 0 || pkt.ID == 0 {
		return
	}
	if pkt.From == b.cfg.BridgeNodeID {
		return
	}
	if pkt.Channel != uint32(b.channelHash) {
		return
	}
	now := b.now()
	if b.isSeen(pkt.From, pkt.ID, now) {
		return
	}

	data, err := b.decodePayload(pkt)
	if err != nil || data == nil {
		return
	}

	switch data.Portnum {
	case PortNumNodeInfoApp:
		user, uerr := UnmarshalUser(data.Payload)
		if uerr != nil {
			return
		}
		if !isValidUserStrings(user) {
			return
		}
		b.markSeen(pkt.From, pkt.ID, now)
		b.nodedb.UpdateUser(pkt.From, user.ShortName, user.LongName, now)
		if b.logger != nil {
			b.logger.Debugf("meshtastic inbound nodeinfo: from=%s short=%q long=%q",
				FormatNodeBang(pkt.From), user.ShortName, user.LongName)
		}
		if data.WantResponse && pkt.To == b.cfg.BridgeNodeID {
			b.maybeReplyNodeInfo(pkt.From, pkt.ID, now)
		}
	case PortNumTextMessageApp:
		b.deliverInboundText(pkt, data, now)
	}
}

func (b *Bridge) handleExternalInboundPacket(pkt *MeshPacket) {
	if pkt == nil || pkt.From == 0 || pkt.ID == 0 || pkt.Decoded == nil {
		return
	}
	st := b.externalState()
	if st.NodeID != 0 && pkt.From == st.NodeID {
		return
	}
	now := b.now()
	if b.isSeen(pkt.From, pkt.ID, now) {
		return
	}

	data := pkt.Decoded
	switch data.Portnum {
	case PortNumNodeInfoApp:
		// NodeInfo is node-global across channels on an external Meshtastic node.
		user, uerr := UnmarshalUser(data.Payload)
		if uerr != nil {
			return
		}
		if !isValidUserStrings(user) {
			return
		}
		b.markSeen(pkt.From, pkt.ID, now)
		b.nodedb.UpdateUser(pkt.From, user.ShortName, user.LongName, now)
		if b.logger != nil {
			b.logger.Debugf("meshtastic inbound nodeinfo: from=%s short=%q long=%q",
				FormatNodeBang(pkt.From), user.ShortName, user.LongName)
		}
	case PortNumTextMessageApp:
		// Over PhoneAPI, pkt.Channel is the local channel index (0..7), never the hash.
		if !st.ChannelResolved || pkt.Channel != st.ChannelIndex {
			return
		}
		b.deliverInboundText(pkt, data, now)
	}
}

func (b *Bridge) deliverInboundText(pkt *MeshPacket, data *Data, now time.Time) {
	// Only bridge broadcast channel messages; never leak DMs into group chat.
	if pkt.To != BroadcastAddr {
		return
	}
	if len(data.Payload) == 0 || bytes.IndexByte(data.Payload, 0) >= 0 || !utf8.Valid(data.Payload) {
		return
	}
	b.markSeen(pkt.From, pkt.ID, now)
	if b.nodedb.IsBanned(pkt.From) {
		if b.logger != nil {
			b.logger.Infof("meshtastic dropping message from banned node %s", FormatNodeBang(pkt.From))
		}
		return
	}
	b.nodedb.Touch(pkt.From, now)
	if b.logger != nil {
		b.logger.Infof("meshtastic inbound text: from=%s pkt_id=0x%08x len=%d via_mqtt=%v",
			FormatNodeBang(pkt.From), pkt.ID, len(data.Payload), pkt.ViaMQTT)
	}
	if b.onMessage != nil {
		b.onMessage(InboundMessage{
			From:     pkt.From,
			PacketID: pkt.ID,
			Text:     string(data.Payload),
			ReplyID:  data.ReplyID,
			Emoji:    data.Emoji,
		})
	}
}

func isValidUserStrings(u *User) bool {
	return utf8.ValidString(u.ID) && !strings.ContainsRune(u.ID, '\x00') &&
		utf8.ValidString(u.ShortName) && !strings.ContainsRune(u.ShortName, '\x00') &&
		utf8.ValidString(u.LongName) && !strings.ContainsRune(u.LongName, '\x00')
}

func (b *Bridge) decodePayload(pkt *MeshPacket) (*Data, error) {
	if len(b.cfg.ExpandedKey) > 0 {
		if pkt.Decoded != nil {
			return nil, fmt.Errorf("plaintext packet rejected on encrypted channel")
		}
		if len(pkt.Encrypted) == 0 {
			return nil, fmt.Errorf("empty encrypted payload")
		}
		plain, err := CryptPacket(pkt.Encrypted, pkt.ID, pkt.From, b.cfg.ExpandedKey)
		if err != nil {
			return nil, err
		}
		return UnmarshalData(plain)
	}
	if pkt.Decoded != nil {
		return pkt.Decoded, nil
	}
	return nil, fmt.Errorf("encrypted packet rejected on unencrypted channel")
}

func (b *Bridge) maybeReplyNodeInfo(toNode, reqID uint32, now time.Time) {
	b.nodeInfoReplyMu.Lock()
	if !b.lastNodeReply.IsZero() && now.Sub(b.lastNodeReply) < nodeInfoReplyMinWait {
		b.nodeInfoReplyMu.Unlock()
		return
	}
	b.lastNodeReply = now
	b.nodeInfoReplyMu.Unlock()
	b.SendNodeInfo(toNode, reqID)
}

func (b *Bridge) isSeen(from, pktID uint32, now time.Time) bool {
	key := (uint64(from) << 32) | uint64(pktID)
	b.dedupMu.Lock()
	exp, ok := b.dedup[key]
	b.dedupMu.Unlock()
	return ok && now.Before(exp)
}

func (b *Bridge) markSeen(from, pktID uint32, now time.Time) {
	key := (uint64(from) << 32) | uint64(pktID)
	b.dedupMu.Lock()
	defer b.dedupMu.Unlock()
	if len(b.dedup) >= meshDedupMaxEntries {
		for k, exp := range b.dedup {
			if !now.Before(exp) {
				delete(b.dedup, k)
			}
		}
		if len(b.dedup) >= meshDedupMaxEntries {
			// Clear half if flooded by distinct IDs.
			n := len(b.dedup) / 2
			for k := range b.dedup {
				delete(b.dedup, k)
				n--
				if n <= 0 {
					break
				}
			}
		}
	}
	b.dedup[key] = now.Add(meshDedupWindow)
}

// StatusSummary formats the /mesh command reply. Secret fields (PSK base64 and
// shareable URL) are included ONLY when includeSecrets is true (RoleAdmin).
func (b *Bridge) StatusSummary(includeSecrets bool) string {
	var out strings.Builder
	if b.isExternal() {
		st := b.externalState()
		switch {
		case st.ChannelResolved:
			if h, ok := externalChannelHash(st); ok {
				fmt.Fprintf(&out, "Meshtastic Bridge: #%s (mode external, ch %d, hash 0x%02x)\n", st.ChannelName, st.ChannelIndex, h)
			} else {
				fmt.Fprintf(&out, "Meshtastic Bridge: #%s (mode external, ch %d)\n", st.ChannelName, st.ChannelIndex)
			}
		case st.Connected && st.ChannelError != "":
			fmt.Fprintf(&out, "Meshtastic Bridge: (mode external, %s)\n", st.ChannelError)
		case b.cfg.ChannelName != "":
			fmt.Fprintf(&out, "Meshtastic Bridge: #%s (mode external, connecting)\n", b.cfg.ChannelName)
		case b.cfg.TCPChannelIndex != nil:
			fmt.Fprintf(&out, "Meshtastic Bridge: ch %d (mode external, connecting)\n", *b.cfg.TCPChannelIndex)
		default:
			out.WriteString("Meshtastic Bridge: (mode external, connecting)\n")
		}

		if st.NodeID != 0 {
			if st.ShortName != "" || st.LongName != "" {
				fmt.Fprintf(&out, "External node: %s (%s / %s)\n", FormatNodeBang(st.NodeID), st.ShortName, st.LongName)
			} else {
				fmt.Fprintf(&out, "External node: %s\n", FormatNodeBang(st.NodeID))
			}
		} else {
			out.WriteString("External node: (not connected)\n")
		}

		addr := DefaultTCPAddr
		state := "connecting"
		if b.tcp != nil {
			addr = b.tcp.Addr()
			if b.tcp.Connected() {
				state = "connected"
			}
		} else if b.cfg.TCPAddr != "" {
			addr = b.cfg.TCPAddr
		}
		fmt.Fprintf(&out, "Transports: TCP(%s, %s)", addr, state)

		if includeSecrets && st.ChannelResolved {
			pskDisplay := "none"
			if len(st.RawPSK) > 0 {
				pskDisplay = base64.StdEncoding.EncodeToString(st.RawPSK)
			}
			fmt.Fprintf(&out, "\nPSK: %s", pskDisplay)
			fmt.Fprintf(&out, "\nURL: %s", FormatChannelURL(st.ChannelName, st.RawPSK))
		}
	} else {
		fmt.Fprintf(&out, "Meshtastic Bridge: #%s (hash 0x%02x)\n", b.cfg.ChannelName, b.channelHash)
		fmt.Fprintf(&out, "Bridge node: %s (%s / %s)\n",
			FormatNodeBang(b.cfg.BridgeNodeID), b.cfg.ShortName, b.cfg.LongName)

		var trParts []string
		if b.udp != nil {
			addr := b.cfg.UDPAddr
			if addr == "" {
				addr = DefaultUDPAddr
			}
			trParts = append(trParts, fmt.Sprintf("UDP(%s)", addr))
		}
		if b.mqtt != nil {
			state := "connecting"
			if b.mqtt.Connected() {
				state = "connected"
			}
			trParts = append(trParts, fmt.Sprintf("MQTT(%s, %s)", b.cfg.MQTTBroker, state))
		}
		if len(trParts) == 0 {
			trParts = append(trParts, "none")
		}
		fmt.Fprintf(&out, "Transports: %s", strings.Join(trParts, ", "))

		if includeSecrets {
			pskDisplay := "none"
			if len(b.cfg.RawPSK) > 0 {
				pskDisplay = base64.StdEncoding.EncodeToString(b.cfg.RawPSK)
			}
			fmt.Fprintf(&out, "\nPSK: %s", pskDisplay)
			fmt.Fprintf(&out, "\nURL: %s", FormatChannelURL(b.cfg.ChannelName, b.cfg.RawPSK))
		}
	}

	recent := b.nodedb.RecentNodes(10)
	if len(recent) > 0 {
		fmt.Fprintf(&out, "\nRecent nodes (%d):", len(recent))
		for _, n := range recent {
			label := b.nodedb.FormatSenderLabel(n.NodeID, b.cfg.LongNameFormat)
			fmt.Fprintf(&out, "\n  [%s] %s", label, FormatNodeBang(n.NodeID))
		}
	} else {
		out.WriteString("\nNo Meshtastic nodes heard yet.")
	}

	if banned := b.nodedb.Banlist(); len(banned) > 0 {
		fmt.Fprintf(&out, "\nBanned mesh nodes: %s", strings.Join(banned, ", "))
	}
	return out.String()
}
