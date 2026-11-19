package meshtastic

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

func TestNormalizeTCPAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", DefaultTCPAddr, false},
		{"127.0.0.1:4403", "127.0.0.1:4403", false},
		{"192.168.1.50", "192.168.1.50:4403", false},
		{"meshtastic.local", "meshtastic.local:4403", false},
		{"tcp://10.0.0.5:4404", "10.0.0.5:4404", false},
		{"tcp://10.0.0.5", "10.0.0.5:4403", false},
		{"::1", "[::1]:4403", false},
		{"[::1]:4405", "[::1]:4405", false},
		{"http://127.0.0.1:4403", "", true},
		{":4403", "", true},
		{"127.0.0.1:99999", "", true},
		{"127.0.0.1:0", "", true},
		{"bad host:4403", "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeTCPAddr(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeTCPAddr(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeTCPAddr(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeTCPAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadStreamFrameResyncAndFraming(t *testing.T) {
	payload1 := (&FromRadio{ID: 1, Rebooted: true}).Marshal()
	payload2 := (&FromRadio{ID: 2, ConfigCompleteID: 99, HasConfigCompleteID: true}).Marshal()

	var wire bytes.Buffer
	// 1. Interleaved ASCII debug logs before frame 1.
	wire.WriteString("INFO  | boot meshtasticd\r\n")
	// 2. Stray START1 immediately before real START1+START2 (0x94 0x94 0xC3 ...).
	wire.WriteByte(streamStart1)
	wire.Write(frameStreamPacket(payload1))
	// 3. False header 0x94 0xC3 followed immediately by real 0x94 0xC3 <len> (length 0x94C3 > 512).
	wire.Write([]byte{streamStart1, streamStart2})
	wire.Write(frameStreamPacket(payload2))
	// 4. Bogus oversized length (> 512) followed by a valid zero-length frame.
	wire.Write([]byte{streamStart1, streamStart2, 0x05, 0x00})
	wire.Write(frameStreamPacket(nil))

	br := bufio.NewReader(&wire)

	got1, err := readStreamFrame(br)
	if err != nil || !bytes.Equal(got1, payload1) {
		t.Fatalf("frame 1 = %x err=%v, want %x", got1, err, payload1)
	}
	got2, err := readStreamFrame(br)
	if err != nil || !bytes.Equal(got2, payload2) {
		t.Fatalf("frame 2 = %x err=%v, want %x", got2, err, payload2)
	}
	got3, err := readStreamFrame(br)
	if err != nil || len(got3) != 0 {
		t.Fatalf("frame 3 = %x err=%v, want empty frame", got3, err)
	}
}

func TestResolveExternalChannel(t *testing.T) {
	primKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	channels := map[int]Channel{
		0: {
			Index:       0,
			Role:        ChannelRolePrimary,
			HasSettings: true,
			Settings:    ChannelSettings{Name: "", PSK: primKey},
		},
		1: {
			Index:       1,
			Role:        ChannelRoleSecondary,
			HasSettings: true,
			Settings:    ChannelSettings{Name: "JPCHAT", PSK: nil}, // inherits primary PSK
		},
		2: {
			Index:       2,
			Role:        ChannelRoleSecondary,
			HasSettings: true,
			Settings:    ChannelSettings{Name: "AEADCh", PSK: []byte{0x01}, UseAEAD: true},
		},
		3: {
			Index: 3,
			Role:  ChannelRoleDisabled,
		},
	}
	lora := &LoRaConfig{UsePreset: true, ModemPreset: 4, HopLimit: 3} // MediumFast

	// 1. Match unnamed primary via preset-derived name ("MediumFast").
	r := resolveExternalChannel(channels, lora, "MediumFast", nil)
	if !r.ok || r.index != 0 || r.name != "MediumFast" || !bytes.Equal(r.rawPSK, primKey) {
		t.Errorf("preset primary match = %+v", r)
	}

	// 2. Match secondary by name (case-insensitive) and verify primary PSK inheritance.
	r = resolveExternalChannel(channels, lora, "jpchat", nil)
	if !r.ok || r.index != 1 || r.name != "JPCHAT" || !bytes.Equal(r.rawPSK, primKey) {
		t.Errorf("secondary keyless inheritance = %+v", r)
	}

	// 3. Explicit channel_index overrides channel_name and preserves UseAEAD.
	idx2 := 2
	r = resolveExternalChannel(channels, lora, "IgnoredName", &idx2)
	if !r.ok || r.index != 2 || r.name != "AEADCh" || !r.useAEAD {
		t.Errorf("explicit channel_index=2 = %+v", r)
	}

	// 4. Explicit disabled channel_index fails closed.
	idx3 := 3
	r = resolveExternalChannel(channels, lora, "", &idx3)
	if r.ok || !strings.Contains(r.errMsg, "DISABLED") {
		t.Errorf("disabled channel_index=3 should fail, got %+v", r)
	}

	// 5. Unknown channel_name fails closed (never silently falls back to ch 0).
	r = resolveExternalChannel(channels, lora, "PrivateRoom", nil)
	if r.ok || !strings.Contains(r.errMsg, "not found") || !strings.Contains(r.errMsg, "0:#MediumFast") || !strings.Contains(r.errMsg, "1:#JPCHAT") {
		t.Errorf("unmatched channel_name should fail closed with available list, got %+v", r)
	}

	// 6. Empty channel_name + nil channel_index selects PRIMARY channel.
	r = resolveExternalChannel(channels, lora, "", nil)
	if !r.ok || r.index != 0 || r.name != "MediumFast" {
		t.Errorf("default primary selection = %+v", r)
	}
}

// mockExternalNode serves a single Meshtastic TCP StreamAPI session over a net.Conn.
type mockExternalNode struct {
	nodeNum   uint32
	shortName string
	longName  string
	channels  []Channel
	lora      *LoRaConfig
	nodes     []*NodeInfo

	replyHeartbeat bool

	txPkts     chan *MeshPacket
	heartbeats chan *Heartbeat
	disconnect chan struct{}
	sendCh     chan *FromRadio
	writeMu    sync.Mutex
}

func newMockExternalNode(nodeNum uint32, shortName, longName string, channels []Channel, lora *LoRaConfig, nodes []*NodeInfo) *mockExternalNode {
	return &mockExternalNode{
		nodeNum:        nodeNum,
		shortName:      shortName,
		longName:       longName,
		channels:       channels,
		lora:           lora,
		nodes:          nodes,
		replyHeartbeat: true,
		txPkts:         make(chan *MeshPacket, 16),
		heartbeats:     make(chan *Heartbeat, 16),
		disconnect:     make(chan struct{}, 1),
		sendCh:         make(chan *FromRadio, 32),
	}
}

func (m *mockExternalNode) sendFrame(conn net.Conn, fr *FromRadio) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := conn.Write(frameStreamPacket(fr.Marshal()))
	return err
}

func (m *mockExternalNode) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	done := make(chan struct{})
	defer close(done)

	// Writer goroutine for async server pushes post-handshake.
	go func() {
		for {
			select {
			case <-done:
				return
			case fr := <-m.sendCh:
				if err := m.sendFrame(conn, fr); err != nil {
					return
				}
			}
		}
	}()

	for {
		raw, err := readStreamFrame(br)
		if err != nil {
			return
		}
		tr, err := UnmarshalToRadio(raw)
		if err != nil {
			continue
		}
		switch {
		case tr.WantConfigID != 0:
			// Emit raw ASCII debug log before protobuf frames to verify StreamAPI resync.
			m.writeMu.Lock()
			_, _ = conn.Write([]byte("INFO | mock meshtasticd ready\n"))
			m.writeMu.Unlock()
			// Emit in exact PhoneAPI.cpp order: MY_INFO -> OWN_NODEINFO -> CHANNELS -> CONFIG -> OTHER_NODEINFOS -> COMPLETE_ID.
			_ = m.sendFrame(conn, &FromRadio{
				ID:     1,
				MyInfo: &MyNodeInfo{MyNodeNum: m.nodeNum, NodeDBCount: uint32(1 + len(m.nodes))},
			})
			_ = m.sendFrame(conn, &FromRadio{
				ID: 2,
				NodeInfo: &NodeInfo{
					Num: m.nodeNum,
					User: &User{
						ID:        FormatNodeBang(m.nodeNum),
						ShortName: m.shortName,
						LongName:  m.longName,
					},
					LastHeard: uint32(time.Now().Unix()),
				},
			})
			for i := range m.channels {
				ch := m.channels[i]
				_ = m.sendFrame(conn, &FromRadio{ID: uint32(10 + i), Channel: &ch})
			}
			if m.lora != nil {
				_ = m.sendFrame(conn, &FromRadio{ID: 20, Config: &RadioConfig{LoRa: m.lora}})
			}
			for i, ni := range m.nodes {
				_ = m.sendFrame(conn, &FromRadio{ID: uint32(30 + i), NodeInfo: ni})
			}
			_ = m.sendFrame(conn, &FromRadio{
				ID:                  99,
				ConfigCompleteID:    tr.WantConfigID,
				HasConfigCompleteID: true,
			})
		case tr.Packet != nil:
			select {
			case m.txPkts <- tr.Packet:
			default:
			}
			_ = m.sendFrame(conn, &FromRadio{
				QueueStatus: &QueueStatus{Res: 0, Free: 15, Maxlen: 16, MeshPacketID: tr.Packet.ID},
			})
		case tr.Heartbeat != nil:
			select {
			case m.heartbeats <- tr.Heartbeat:
			default:
			}
			if m.replyHeartbeat {
				_ = m.sendFrame(conn, &FromRadio{
					QueueStatus: &QueueStatus{Res: 0, Free: 16, Maxlen: 16, MeshPacketID: 0},
				})
			}
		case tr.Disconnect:
			select {
			case m.disconnect <- struct{}{}:
			default:
			}
			return
		}
	}
}

func TestExternalBridgeTCPHandshakeBidirectionalAndSecurity(t *testing.T) {
	node := newMockExternalNode(
		0x43b5a120, "GATE", "Meshtasticd Gateway",
		[]Channel{
			{Index: 0, Role: ChannelRolePrimary, HasSettings: true, Settings: ChannelSettings{Name: "", PSK: []byte{0x01}}},
			{Index: 1, Role: ChannelRoleSecondary, HasSettings: true, Settings: ChannelSettings{Name: "JPCHAT", PSK: []byte{0x01}}},
		},
		&LoRaConfig{UsePreset: true, ModemPreset: 4, HopLimit: 3},
		[]*NodeInfo{
			{
				Num:       0x11223344,
				User:      &User{ID: "!11223344", ShortName: "ALCE", LongName: "Alice"},
				LastHeard: uint32(time.Now().Unix()),
			},
		},
	)

	var gotMu sync.Mutex
	var got []InboundMessage
	gotSig := make(chan InboundMessage, 8)

	b, err := NewBridge(BridgeConfig{
		Mode:             ModeExternal,
		ChannelName:      "JPCHAT",
		TCPAddr:          "127.0.0.1:4403",
		HopLimit:         3,
		LongMessageMode:  "chunk",
		MaxChunks:        3,
		NodeInfoInterval: 50 * time.Millisecond, // must be ignored in external mode
	}, func(m InboundMessage) {
		gotMu.Lock()
		got = append(got, m)
		gotMu.Unlock()
		gotSig <- m
	}, logging.Discard())
	if err != nil {
		t.Fatalf("NewBridge(external): %v", err)
	}

	clientConn, serverConn := net.Pipe()
	go node.serve(serverConn)

	b.TCPTransport().dialFn = func(context.Context, string) (net.Conn, error) {
		return clientConn, nil
	}
	b.TCPTransport().disableTextPacing = true
	b.TCPTransport().heartbeatInterval = 80 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx)
	}()

	select {
	case <-b.TCPTransport().Ready():
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("TCPTransport did not finish handshake")
	}

	// Verify learned identity, channel, and seeded peer NodeInfo (without self in RecentNodes).
	if id := b.BridgeNodeID(); id != 0x43b5a120 {
		t.Errorf("BridgeNodeID = 0x%08x, want 0x43b5a120", id)
	}
	if ch := b.ChannelName(); ch != "JPCHAT" {
		t.Errorf("ChannelName = %q, want JPCHAT", ch)
	}
	if lbl := b.FormatSenderLabel(0x11223344); lbl != "M:ALCE" {
		t.Errorf("seeded peer label = %q, want M:ALCE", lbl)
	}
	for _, n := range b.NodeDB().RecentNodes(10) {
		if n.NodeID == 0x43b5a120 {
			t.Errorf("external node's own ID leaked into NodeDB RecentNodes")
		}
	}

	// 1. Outbound text & reaction: must arrive as Decoded on local channel index 1 (NOT channel hash!), From=0, no synthetic NODEINFO.
	ids := b.SendText("[bob] hello meshtasticd", 0x99990001)
	if len(ids) != 1 {
		t.Fatalf("SendText ids = %v", ids)
	}
	select {
	case pkt := <-node.txPkts:
		if pkt.From != 0 || pkt.To != BroadcastAddr || pkt.Channel != 1 || pkt.ID != ids[0] {
			t.Errorf("outbound pkt header = %+v, want From=0 To=broadcast Channel=1 ID=0x%08x", pkt, ids[0])
		}
		if pkt.Decoded == nil || len(pkt.Encrypted) != 0 {
			t.Fatalf("external outbound pkt must be Decoded plaintext, got %+v", pkt)
		}
		if string(pkt.Decoded.Payload) != "[bob] hello meshtasticd" || pkt.Decoded.ReplyID != 0x99990001 || pkt.Decoded.HasBitfield {
			t.Errorf("outbound decoded Data = %+v", pkt.Decoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound text on mock external node")
	}

	reactID := b.SendReaction("🔥", 0x99990001)
	if reactID == 0 {
		t.Fatal("SendReaction returned 0")
	}
	select {
	case pkt := <-node.txPkts:
		if pkt.Channel != 1 || pkt.Decoded == nil || pkt.Decoded.Emoji != 1 ||
			pkt.Decoded.ReplyID != 0x99990001 || string(pkt.Decoded.Payload) != "🔥" {
			t.Errorf("outbound reaction pkt = %+v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound reaction")
	}

	// Verify SendNodeInfo is a no-op in external mode.
	if niID := b.SendNodeInfo(BroadcastAddr, 0); niID != 0 {
		t.Errorf("SendNodeInfo in external mode returned 0x%08x, want 0", niID)
	}

	// 2. Heartbeat keepalive fires and reaches server.
	select {
	case hb := <-node.heartbeats:
		if hb.Nonce != 0 {
			t.Errorf("heartbeat nonce = %d, want 0", hb.Nonce)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected periodic Heartbeat on TCP session")
	}

	// 3. Inbound NODEINFO_APP on channel 0 still updates NodeDB even though we bridge channel 1.
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x22334455,
			To:      BroadcastAddr,
			Channel: 0,
			ID:      5001,
			Decoded: &Data{
				Portnum: PortNumNodeInfoApp,
				Payload: (&User{ID: "!22334455", ShortName: "CHAR", LongName: "Charlie"}).Marshal(),
			},
		},
	}

	// 4. Filtered packets that MUST NOT deliver:
	//    - wrong channel index (ch 0)
	//    - self echo (From == 0x43b5a120)
	//    - DM (To != BroadcastAddr)
	//    - still-encrypted packet (Decoded == nil)
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x11223344,
			To:      BroadcastAddr,
			Channel: 0,
			ID:      5002,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("wrong channel 0")},
		},
	}
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x43b5a120,
			To:      BroadcastAddr,
			Channel: 1,
			ID:      5003,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("self echo")},
		},
	}
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x11223344,
			To:      0x43b5a120,
			Channel: 1,
			ID:      5004,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("private dm")},
		},
	}
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:      0x11223344,
			To:        BroadcastAddr,
			Channel:   1,
			ID:        5005,
			Encrypted: []byte{1, 2, 3, 4},
		},
	}

	// 5. Valid broadcast on channel 1 (plus duplicate that must dedup).
	validPkt := &MeshPacket{
		From:    0x22334455,
		To:      BroadcastAddr,
		Channel: 1,
		ID:      5006,
		Decoded: &Data{
			Portnum: PortNumTextMessageApp,
			Payload: []byte("hello from rf"),
			ReplyID: ids[0],
		},
	}
	node.sendCh <- &FromRadio{Packet: validPkt}
	node.sendCh <- &FromRadio{Packet: validPkt}

	select {
	case msg := <-gotSig:
		if msg.From != 0x22334455 || msg.Text != "hello from rf" || msg.ReplyID != ids[0] {
			t.Errorf("unexpected inbound message: %+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inbound message on channel 1")
	}

	// Wait briefly to confirm filtered/duplicate messages did not arrive.
	time.Sleep(50 * time.Millisecond)
	gotMu.Lock()
	if len(got) != 1 {
		t.Errorf("got %d messages (%+v), want 1", len(got), got)
	}
	gotMu.Unlock()
	if lbl := b.FormatSenderLabel(0x22334455); lbl != "M:CHAR" {
		t.Errorf("ch0 NODEINFO label = %q, want M:CHAR", lbl)
	}

	// 6. Banning !22334455 drops subsequent messages.
	if _, _, err := b.NodeDB().Ban("!22334455"); err != nil {
		t.Fatal(err)
	}
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x22334455,
			To:      BroadcastAddr,
			Channel: 1,
			ID:      5007,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("banned")},
		},
	}
	time.Sleep(50 * time.Millisecond)
	gotMu.Lock()
	if len(got) != 1 {
		t.Errorf("banned node message delivered: %+v", got)
	}
	gotMu.Unlock()

	// 7. StatusSummary: non-admin hides PSK/URL; admin sees external node & channel PSK/URL.
	memberStatus := b.StatusSummary(false)
	if !strings.Contains(memberStatus, "mode external") || !strings.Contains(memberStatus, "#JPCHAT") ||
		!strings.Contains(memberStatus, "!43b5a120") || !strings.Contains(memberStatus, "TCP(127.0.0.1:4403, connected)") {
		t.Errorf("member StatusSummary unexpected:\n%s", memberStatus)
	}
	if strings.Contains(memberStatus, "PSK:") || strings.Contains(memberStatus, "https://meshtastic.org/e/#") {
		t.Errorf("member StatusSummary leaked secrets:\n%s", memberStatus)
	}
	adminStatus := b.StatusSummary(true)
	if !strings.Contains(adminStatus, "PSK: AQ==") || !strings.Contains(adminStatus, "https://meshtastic.org/e/#") {
		t.Errorf("admin StatusSummary missing external channel PSK/URL:\n%s", adminStatus)
	}

	// 8. Clean shutdown sends ToRadio{Disconnect: true} and exits promptly.
	cancel()
	select {
	case <-node.disconnect:
	case <-time.After(1 * time.Second):
		t.Error("expected ToRadio{Disconnect: true} on shutdown")
	}
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Bridge.Run did not exit cleanly after cancel")
	}
}

func TestTCPTransportUnmatchedChannelRefusesTxAndRx(t *testing.T) {
	node := newMockExternalNode(
		0x10203040, "NODE", "Only LongFast",
		[]Channel{
			{Index: 0, Role: ChannelRolePrimary, HasSettings: true, Settings: ChannelSettings{Name: "", PSK: []byte{0x01}}},
		},
		&LoRaConfig{UsePreset: true, ModemPreset: 0, HopLimit: 3},
		nil,
	)

	var gotCount atomic.Int32
	b, err := NewBridge(BridgeConfig{
		Mode:        ModeExternal,
		ChannelName: "PrivateOnly",
		TCPAddr:     "127.0.0.1:4403",
	}, func(InboundMessage) {
		gotCount.Add(1)
	}, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	go node.serve(serverConn)
	b.TCPTransport().dialFn = func(context.Context, string) (net.Conn, error) { return clientConn, nil }
	b.TCPTransport().disableTextPacing = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	select {
	case <-b.TCPTransport().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// Outbound send must fail closed (never leak onto ch 0!).
	if err := b.TCPTransport().Send(ctx, &MeshPacket{
		To:      BroadcastAddr,
		ID:      123,
		Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("secret")},
	}); err == nil {
		t.Fatal("expected Send to fail when target channel_name was not found on external node")
	}

	// Inbound packet on ch 0 must also be ignored.
	node.sendCh <- &FromRadio{
		Packet: &MeshPacket{
			From:    0x99887766,
			To:      BroadcastAddr,
			Channel: 0,
			ID:      321,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("public ch0")},
		},
	}
	time.Sleep(50 * time.Millisecond)
	if gotCount.Load() != 0 {
		t.Errorf("expected 0 inbound messages on unresolved channel, got %d", gotCount.Load())
	}
	if status := b.StatusSummary(true); !strings.Contains(status, "not found") || strings.Contains(status, "PSK:") {
		t.Errorf("unexpected StatusSummary for unresolved channel:\n%s", status)
	}
}

func TestTCPTransportTextRateLimitPacing(t *testing.T) {
	node := newMockExternalNode(
		0x10203040, "NODE", "Paced Node",
		[]Channel{
			{Index: 0, Role: ChannelRolePrimary, HasSettings: true, Settings: ChannelSettings{Name: "LongFast", PSK: []byte{0x01}}},
		},
		&LoRaConfig{UsePreset: true, ModemPreset: 0, HopLimit: 3},
		nil,
	)

	clientConn, serverConn := net.Pipe()
	go node.serve(serverConn)

	tr := NewTCPTransport("127.0.0.1:4403", "LongFast", nil, logging.Discard())
	tr.dialFn = func(context.Context, string) (net.Conn, error) { return clientConn, nil }
	tr.textMinInterval = 120 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Run(ctx, nil) }()

	select {
	case <-tr.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("TCPTransport not ready")
	}

	t0 := time.Now()
	for i := uint32(1); i <= 2; i++ {
		if err := tr.Send(ctx, &MeshPacket{
			To:      BroadcastAddr,
			ID:      i,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("chunk")},
		}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	elapsed := time.Since(t0)
	if elapsed < 100*time.Millisecond {
		t.Errorf("back-to-back text sends completed in %s, want >= 100ms pacing", elapsed)
	}
}

func TestTCPTransportRebootedReconnectsAndCloseDoesNotDeadlockBehindHungWrite(t *testing.T) {
	// 1. Rebooted triggers a fresh reconnect & handshake.
	var dialCount atomic.Int32
	node1 := newMockExternalNode(
		0x11111111, "N1", "Node One",
		[]Channel{{Index: 0, Role: ChannelRolePrimary, HasSettings: true, Settings: ChannelSettings{Name: "LongFast", PSK: []byte{0x01}}}},
		nil, nil,
	)
	node2 := newMockExternalNode(
		0x22222222, "N2", "Node Two",
		[]Channel{{Index: 0, Role: ChannelRolePrimary, HasSettings: true, Settings: ChannelSettings{Name: "LongFast", PSK: []byte{0x01}}}},
		nil, nil,
	)

	reconnected := make(chan uint32, 4)
	var activeStall *stallWriteConn
	var stallMu sync.Mutex

	tr := NewTCPTransport("127.0.0.1:4403", "LongFast", nil, logging.Discard())
	tr.disableTextPacing = true
	tr.onState = func(st ExternalNodeState) {
		if st.Connected && st.NodeID != 0 {
			select {
			case reconnected <- st.NodeID:
			default:
			}
		}
	}
	tr.dialFn = func(context.Context, string) (net.Conn, error) {
		n := dialCount.Add(1)
		c, s := net.Pipe()
		if n == 1 {
			go node1.serve(s)
			return c, nil
		}
		sc := &stallWriteConn{
			Conn:        c,
			writePaused: make(chan struct{}),
			closed:      make(chan struct{}),
		}
		stallMu.Lock()
		activeStall = sc
		stallMu.Unlock()
		go node2.serve(s)
		return sc, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = tr.Run(ctx, nil)
	}()

	select {
	case id := <-reconnected:
		if id != 0x11111111 {
			t.Fatalf("first connect nodeID = 0x%08x, want 0x11111111", id)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("first connect timed out")
	}

	// Trigger remote reboot notification -> TCPTransport must close and reconnect cleanly.
	node1.sendCh <- &FromRadio{Rebooted: true}

	select {
	case id := <-reconnected:
		if id != 0x22222222 {
			t.Fatalf("second connect nodeID = 0x%08x, want 0x22222222", id)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("reconnect after Rebooted timed out")
	}

	// 2. Now stall a write on session 2 and verify ctx cancel unblocks immediately (non-blocking teardown invariant).
	stallMu.Lock()
	sc := activeStall
	stallMu.Unlock()
	sc.stall.Store(true)

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- tr.Send(ctx, &MeshPacket{
			To:      BroadcastAddr,
			ID:      0x4242,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("blocked")},
		})
	}()

	select {
	case <-sc.writePaused:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("TCP Send did not enter Write")
	}

	cancel()

	select {
	case err := <-sendErr:
		if err == nil {
			t.Fatal("expected error from interrupted TCP Send")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TCP Send remained blocked after context cancel")
	}

	select {
	case <-runDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TCPTransport.Run remained blocked after context cancel")
	}
}
