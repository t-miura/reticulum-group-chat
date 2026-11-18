package meshtastic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

// memPacketConn implements net.PacketConn in memory so UDPTransport.Run/Send
// can be tested without opening OS sockets.
type memPacketConn struct {
	ch     chan []byte
	peer   *memPacketConn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newMemPacketConnPair() (*memPacketConn, *memPacketConn) {
	a := &memPacketConn{
		ch:     make(chan []byte, 16),
		addr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4403},
		closed: make(chan struct{}),
	}
	b := &memPacketConn{
		ch:     make(chan []byte, 16),
		addr:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4404},
		closed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-m.closed:
		return 0, nil, net.ErrClosed
	case data := <-m.ch:
		n := copy(p, data)
		return n, m.peer.addr, nil
	}
}

func (m *memPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-m.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := append([]byte(nil), p...)
	select {
	case m.peer.ch <- cp:
		return len(p), nil
	case <-m.closed:
		return 0, net.ErrClosed
	}
}

func (m *memPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}
func (m *memPacketConn) LocalAddr() net.Addr              { return m.addr }
func (m *memPacketConn) SetDeadline(time.Time) error      { return nil }
func (m *memPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPLoopbackSendAndReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recvConn, sendConn := newMemPacketConnPair()
	tr := NewUDPTransport(DefaultUDPAddr, "", logging.Discard())
	tr.openConns = func() (net.PacketConn, net.PacketConn, net.Addr, error) {
		return recvConn, sendConn, recvConn.LocalAddr(), nil
	}
	gotCh := make(chan *MeshPacket, 4)

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx, func(pkt *MeshPacket) {
			gotCh <- pkt
		})
	}()

	select {
	case <-tr.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("UDPTransport did not initialize in time")
	}

	pkt := &MeshPacket{
		From:    0x11223344,
		To:      BroadcastAddr,
		Channel: 8,
		ID:      0x55667788,
		Decoded: &Data{
			Portnum: PortNumTextMessageApp,
			Payload: []byte("hello loopback udp"),
		},
	}
	if err := tr.Send(ctx, pkt); err != nil {
		t.Fatalf("UDP Send: %v", err)
	}

	select {
	case got := <-gotCh:
		if got.From != pkt.From || got.ID != pkt.ID || string(got.Decoded.Payload) != "hello loopback udp" {
			t.Errorf("received unexpected packet: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP packet")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("UDP Run returned err: %v", err)
	}
}

func TestMQTTTransportSessionAndEnvelope(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	type published struct {
		topic   string
		payload []byte
	}
	brokerGotPub := make(chan published, 4)
	subDone := make(chan struct{}, 1)

	go func() {
		defer serverConn.Close()
		br := bufio.NewReader(serverConn)

		// Expect CONNECT
		ptype, _, _, rerr := readMQTTPacket(br)
		if rerr != nil || ptype != 1 {
			return
		}
		// Send CONNACK (accepted)
		_, _ = serverConn.Write([]byte{0x20, 0x02, 0x00, 0x00})

		// Expect SUBSCRIBE
		ptype, _, body, rerr := readMQTTPacket(br)
		if rerr != nil || ptype != 8 || len(body) < 2 {
			return
		}
		pid := binary.BigEndian.Uint16(body[:2])
		// Send SUBACK (QoS 0 granted)
		_, _ = serverConn.Write([]byte{0x90, 0x03, byte(pid >> 8), byte(pid), 0x00})
		close(subDone)

		// Push a mismatched ChannelID envelope first (must be skipped).
		wrongEnv := &ServiceEnvelope{
			ChannelID: "OtherChan",
			GatewayID: "!99887766",
			Packet: &MeshPacket{
				From:    0x99887766,
				To:      BroadcastAddr,
				Channel: 8,
				ID:      0x01020309,
				Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("wrong channel")},
			},
		}
		var wrongBody []byte
		wrongBody = appendMQTTString(wrongBody, "msh/US/2/e/LongFast/!99887766")
		wrongBody = append(wrongBody, wrongEnv.Marshal()...)
		_, _ = serverConn.Write(frameMQTTPacket(3, 0x00, wrongBody))

		// Push an inbound QoS-1 PUBLISH to client so PUBACK path is also tested.
		inEnv := &ServiceEnvelope{
			ChannelID: "LongFast",
			GatewayID: "!99887766",
			Packet: &MeshPacket{
				From:    0x99887766,
				To:      BroadcastAddr,
				Channel: 8,
				ID:      0x01020304,
				Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("from broker")},
			},
		}
		var qos1Body []byte
		qos1Body = appendMQTTString(qos1Body, "msh/US/2/e/LongFast/!99887766")
		qos1Body = binary.BigEndian.AppendUint16(qos1Body, 42) // packet id
		qos1Body = append(qos1Body, inEnv.Marshal()...)
		_, _ = serverConn.Write(frameMQTTPacket(3, 0x02, qos1Body))

		for {
			pt, fl, pb, err := readMQTTPacket(br)
			if err != nil {
				return
			}
			switch pt {
			case 3:
				qos := (fl >> 1) & 0x03
				topic, _, pl, decErr := decodeMQTTPublish(pb, qos)
				if decErr == nil {
					brokerGotPub <- published{topic: topic, payload: append([]byte(nil), pl...)}
				}
			case 12: // PINGREQ
				_, _ = serverConn.Write([]byte{0xD0, 0x00})
			case 14: // DISCONNECT
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mq := NewMQTTTransport("tcp://mock.broker:1883", "user", "pass", "msh/US", "LongFast", "aabbccdd", logging.Discard())
	mq.dialFn = func(context.Context, string) (net.Conn, error) {
		return clientConn, nil
	}
	gotCh := make(chan *MeshPacket, 4)
	go func() {
		_ = mq.Run(ctx, func(p *MeshPacket) {
			gotCh <- p
		})
	}()

	select {
	case <-mq.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("MQTTTransport did not subscribe in time")
	}
	<-subDone

	select {
	case pkt := <-gotCh:
		if pkt.From != 0x99887766 || string(pkt.Decoded.Payload) != "from broker" {
			t.Errorf("unexpected inbound MQTT packet: %+v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inbound MQTT packet")
	}

	outPkt := &MeshPacket{
		From:    0xaabbccdd,
		To:      BroadcastAddr,
		Channel: 8,
		ID:      0x11223344,
		Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("to broker")},
	}
	if err := mq.Send(ctx, outPkt); err != nil {
		t.Fatalf("MQTT Send: %v", err)
	}

	select {
	case pub := <-brokerGotPub:
		if pub.topic != "msh/US/2/e/LongFast/!aabbccdd" {
			t.Errorf("published topic = %q", pub.topic)
		}
		env, err := UnmarshalServiceEnvelope(pub.payload)
		if err != nil || env.Packet == nil || string(env.Packet.Decoded.Payload) != "to broker" {
			t.Errorf("published envelope mismatch: %+v err=%v", env, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not receive outbound PUBLISH")
	}
}

// fakeMeshTransport captures outbound sends and injects inbound packets for Bridge tests.
type fakeMeshTransport struct {
	name string

	mu   sync.Mutex
	sent []*MeshPacket
	onRx func(*MeshPacket)
}

func (f *fakeMeshTransport) Name() string { return f.name }

func (f *fakeMeshTransport) Run(ctx context.Context, onPacket func(*MeshPacket)) error {
	f.mu.Lock()
	f.onRx = onPacket
	f.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (f *fakeMeshTransport) Send(_ context.Context, pkt *MeshPacket) error {
	f.mu.Lock()
	f.sent = append(f.sent, pkt)
	f.mu.Unlock()
	return nil
}

func (f *fakeMeshTransport) inject(pkt *MeshPacket) {
	f.mu.Lock()
	cb := f.onRx
	f.mu.Unlock()
	if cb != nil {
		cb(pkt)
	}
}

func (f *fakeMeshTransport) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func makeEncryptedMeshPacket(t *testing.T, from, to, pktID uint32, chHash uint8, key []byte, data *Data) *MeshPacket {
	t.Helper()
	enc, err := CryptPacket(data.Marshal(), pktID, from, key)
	if err != nil {
		t.Fatal(err)
	}
	return &MeshPacket{
		From:      from,
		To:        to,
		Channel:   uint32(chHash),
		ID:        pktID,
		Encrypted: enc,
	}
}

func TestBridgeEndpointDedupNodeInfoBanAndSecrets(t *testing.T) {
	rawPSK, expKey, err := ParsePSK("AQ==")
	if err != nil {
		t.Fatal(err)
	}

	var gotMu sync.Mutex
	var got []InboundMessage

	b, err := NewBridge(BridgeConfig{
		ChannelName:     "LongFast",
		RawPSK:          rawPSK,
		ExpandedKey:     expKey,
		BridgeNodeID:    0xaabbccdd,
		ShortName:       "RNS",
		LongName:        "Test Bridge",
		HopLimit:        3,
		OKToMQTT:        true,
		LongMessageMode: "chunk",
		MaxChunks:       3,
	}, func(m InboundMessage) {
		gotMu.Lock()
		got = append(got, m)
		gotMu.Unlock()
	}, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}

	udpFake := &fakeMeshTransport{name: "udp"}
	mqttFake := &fakeMeshTransport{name: "mqtt"}
	b.transports = []Transport{udpFake, mqttFake}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	time.Sleep(30 * time.Millisecond)

	chHash := b.ChannelHash()

	// 1. NODEINFO_APP from peer 0x11223344 with want_response targeting bridge node.
	nodeInfoUser := &User{ID: "!11223344", ShortName: "ALCE", LongName: "Alice"}
	niPkt := makeEncryptedMeshPacket(t, 0x11223344, b.BridgeNodeID(), 1001, chHash, expKey, &Data{
		Portnum:      PortNumNodeInfoApp,
		Payload:      nodeInfoUser.Marshal(),
		WantResponse: true,
	})
	udpFake.inject(niPkt)
	if lbl := b.FormatSenderLabel(0x11223344); lbl != "M:ALCE" {
		t.Errorf("FormatSenderLabel = %q, want M:ALCE", lbl)
	}
	time.Sleep(30 * time.Millisecond)
	if udpFake.sentCount() != 1 || mqttFake.sentCount() != 1 {
		t.Errorf("WantResponse should send NODEINFO reply on both transports: udp=%d mqtt=%d", udpFake.sentCount(), mqttFake.sentCount())
	}

	// 2. Same broadcast text injected on BOTH UDP and MQTT -> deduplicated to 1 delivery
	// AND never cross-repeated from UDP to MQTT or vice versa.
	txtPkt := makeEncryptedMeshPacket(t, 0x11223344, BroadcastAddr, 2002, chHash, expKey, &Data{
		Portnum: PortNumTextMessageApp,
		Payload: []byte("hello from mesh"),
	})
	udpFake.inject(txtPkt)
	mqttFake.inject(txtPkt)

	gotMu.Lock()
	if len(got) != 1 || got[0].Text != "hello from mesh" {
		t.Fatalf("expected 1 deduplicated message, got %+v", got)
	}
	gotMu.Unlock()
	if udpFake.sentCount() != 1 || mqttFake.sentCount() != 1 {
		t.Errorf("third-party inbound packet must NOT cross-relay: udp=%d mqtt=%d", udpFake.sentCount(), mqttFake.sentCount())
	}

	// 3. Self-originated packet, DM (To != BroadcastAddr), wrong channel hash, wrong key -> all ignored.
	udpFake.inject(makeEncryptedMeshPacket(t, b.BridgeNodeID(), BroadcastAddr, 3003, chHash, expKey, &Data{
		Portnum: PortNumTextMessageApp, Payload: []byte("self echo"),
	}))
	udpFake.inject(makeEncryptedMeshPacket(t, 0x11223344, 0x55667788, 3004, chHash, expKey, &Data{
		Portnum: PortNumTextMessageApp, Payload: []byte("private dm"),
	}))
	udpFake.inject(makeEncryptedMeshPacket(t, 0x11223344, BroadcastAddr, 3005, chHash+1, expKey, &Data{
		Portnum: PortNumTextMessageApp, Payload: []byte("other channel"),
	}))
	udpFake.inject(makeEncryptedMeshPacket(t, 0x11223344, BroadcastAddr, 3006, chHash, bytes.Repeat([]byte{0x77}, 16), &Data{
		Portnum: PortNumTextMessageApp, Payload: []byte("wrong key"),
	}))

	gotMu.Lock()
	if len(got) != 1 {
		t.Errorf("expected ignored packets not to deliver, got %+v", got)
	}
	gotMu.Unlock()

	// 4. Banning !11223344 drops future packets from that node.
	if _, _, err := b.NodeDB().Ban("!11223344"); err != nil {
		t.Fatal(err)
	}
	udpFake.inject(makeEncryptedMeshPacket(t, 0x11223344, BroadcastAddr, 4007, chHash, expKey, &Data{
		Portnum: PortNumTextMessageApp, Payload: []byte("banned speech"),
	}))
	gotMu.Lock()
	if len(got) != 1 {
		t.Errorf("banned node message was delivered: %+v", got)
	}
	gotMu.Unlock()

	// 5. StatusSummary hides PSK/URL for members, shows for admins.
	memberSummary := b.StatusSummary(false)
	if strings.Contains(memberSummary, "PSK:") || strings.Contains(memberSummary, "https://meshtastic.org/e/#") {
		t.Errorf("non-admin StatusSummary leaked secret: %q", memberSummary)
	}
	adminSummary := b.StatusSummary(true)
	if !strings.Contains(adminSummary, "PSK: AQ==") || !strings.Contains(adminSummary, "https://meshtastic.org/e/#") {
		t.Errorf("admin StatusSummary missing PSK/URL: %q", adminSummary)
	}
}

func TestRankMulticastCandidatesPrefersLANOverVirtual(t *testing.T) {
	cands := []multicastCandidate{
		{iface: net.Interface{Index: 2, Name: "utun0"}, ip4: net.IPv4(10, 8, 0, 2)},
		{iface: net.Interface{Index: 3, Name: "awdl0"}, ip4: net.IPv4(169, 254, 1, 1)},
		{iface: net.Interface{Index: 4, Name: "bridge0"}, ip4: net.IPv4(192, 168, 64, 1)},
		{iface: net.Interface{Index: 5, Name: "en0"}, ip4: net.IPv4(192, 168, 1, 50)},
		{iface: net.Interface{Index: 6, Name: "eth0"}, ip4: net.IPv4(10, 0, 0, 5)},
	}
	primary, all, err := rankMulticastCandidates(cands)
	if err != nil {
		t.Fatal(err)
	}
	if primary == nil || primary.Name != "en0" {
		t.Fatalf("primary = %+v, want en0", primary)
	}
	if len(all) != len(cands) {
		t.Errorf("all len = %d, want %d", len(all), len(cands))
	}
}

func TestBridgeRejectsPlaintextOnEncryptedAndCorruptDoesNotPoisonDedup(t *testing.T) {
	rawPSK, expKey, err := ParsePSK("AQ==")
	if err != nil {
		t.Fatal(err)
	}

	var gotMu sync.Mutex
	var got []InboundMessage
	b, err := NewBridge(BridgeConfig{
		ChannelName:  "LongFast",
		RawPSK:       rawPSK,
		ExpandedKey:  expKey,
		BridgeNodeID: 0xaabbccdd,
		ShortName:    "RNS",
		LongName:     "Test",
	}, func(m InboundMessage) {
		gotMu.Lock()
		got = append(got, m)
		gotMu.Unlock()
	}, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	tr := &fakeMeshTransport{name: "mock"}
	b.SetTransports(tr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	time.Sleep(20 * time.Millisecond)

	chHash := b.ChannelHash()

	// 1. Plaintext Decoded packet must be rejected when channel has a PSK.
	tr.inject(&MeshPacket{
		From:    0x55555555,
		To:      BroadcastAddr,
		Channel: uint32(chHash),
		ID:      776,
		Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("unencrypted bypass")},
	})

	// 2. Corrupted packet with (0x55555555, 777) must NOT poison dedup cache.
	tr.inject(&MeshPacket{
		From:      0x55555555,
		To:        BroadcastAddr,
		Channel:   uint32(chHash),
		ID:        777,
		Encrypted: []byte{0xff, 0xff, 0xff, 0xff},
	})

	// 3. Real encrypted packet with the same (0x55555555, 777) must succeed.
	tr.inject(makeEncryptedMeshPacket(t, 0x55555555, BroadcastAddr, 777, chHash, expKey, &Data{
		Portnum: PortNumTextMessageApp,
		Payload: []byte("authentic"),
	}))

	gotMu.Lock()
	defer gotMu.Unlock()
	if len(got) != 1 || got[0].Text != "authentic" {
		t.Fatalf("got = %+v, want single authentic message", got)
	}
}

type blockingMeshTransport struct {
	name    string
	started chan struct{}
	once    sync.Once
	release chan struct{}
}

func (b *blockingMeshTransport) Name() string { return b.name }

func (b *blockingMeshTransport) Run(ctx context.Context, _ func(*MeshPacket)) error {
	<-ctx.Done()
	return nil
}

func (b *blockingMeshTransport) Send(ctx context.Context, _ *MeshPacket) error {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type signalMeshTransport struct {
	name   string
	sentCh chan *MeshPacket
}

func (s *signalMeshTransport) Name() string { return s.name }

func (s *signalMeshTransport) Run(ctx context.Context, _ func(*MeshPacket)) error {
	<-ctx.Done()
	return nil
}

func (s *signalMeshTransport) Send(_ context.Context, pkt *MeshPacket) error {
	s.sentCh <- pkt
	return nil
}

func TestBridgeSlowTransportDoesNotStallOtherTransport(t *testing.T) {
	b, err := NewBridge(BridgeConfig{
		ChannelName:  "LongFast",
		BridgeNodeID: 0xaabbccdd,
		ShortName:    "RNS",
		LongName:     "Test",
	}, nil, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}

	slowMQTT := &blockingMeshTransport{
		name:    "mqtt",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	fastUDP := &signalMeshTransport{
		name:   "udp",
		sentCh: make(chan *MeshPacket, 8),
	}
	// Place slowMQTT before fastUDP to verify head-of-line isolation regardless of order.
	b.SetTransports(slowMQTT, fastUDP)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx)
	}()

	ids1 := b.SendText("first", 0)
	ids2 := b.SendText("second", 0)
	if len(ids1) != 1 || len(ids2) != 1 {
		t.Fatalf("unexpected SendText ids: %v %v", ids1, ids2)
	}

	select {
	case <-slowMQTT.started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow transport never received first send")
	}

	for i, wantID := range []uint32{ids1[0], ids2[0]} {
		select {
		case pkt := <-fastUDP.sentCh:
			if pkt.ID != wantID {
				t.Errorf("udp pkt[%d] id = 0x%08x, want 0x%08x", i, pkt.ID, wantID)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("udp transport stalled waiting for slow mqtt transport (pkt %d)", i)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		close(slowMQTT.release)
		t.Fatal("Bridge.Run did not exit promptly after context cancel")
	}
}

type stallWriteConn struct {
	net.Conn
	stall       atomic.Bool
	writePaused chan struct{}
	pausedOnce  sync.Once
	closed      chan struct{}
	closeOnce   sync.Once
}

func (c *stallWriteConn) Write(p []byte) (int, error) {
	if c.stall.Load() {
		c.pausedOnce.Do(func() { close(c.writePaused) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *stallWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestMQTTTransportCloseDoesNotDeadlockBehindHungWrite(t *testing.T) {
	rawClient, serverConn := net.Pipe()
	clientConn := &stallWriteConn{
		Conn:        rawClient,
		writePaused: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	defer serverConn.Close()

	go func() {
		defer serverConn.Close()
		br := bufio.NewReader(serverConn)
		ptype, _, _, rerr := readMQTTPacket(br)
		if rerr != nil || ptype != 1 {
			return
		}
		_, _ = serverConn.Write([]byte{0x20, 0x02, 0x00, 0x00}) // CONNACK
		ptype, _, body, rerr := readMQTTPacket(br)
		if rerr != nil || ptype != 8 || len(body) < 2 {
			return
		}
		pid := binary.BigEndian.Uint16(body[:2])
		_, _ = serverConn.Write([]byte{0x90, 0x03, byte(pid >> 8), byte(pid), 0x00}) // SUBACK
		_, _, _, _ = readMQTTPacket(br)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	mq := NewMQTTTransport("tcp://mock.broker:1883", "", "", "msh/JP", "JPCHAT", "aabbccdd", logging.Discard())
	mq.dialFn = func(context.Context, string) (net.Conn, error) {
		return clientConn, nil
	}

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = mq.Run(ctx, nil)
	}()

	select {
	case <-mq.Ready():
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("MQTTTransport did not reach subscribed state")
	}

	clientConn.stall.Store(true)
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- mq.Send(ctx, &MeshPacket{
			From:    0xaabbccdd,
			To:      BroadcastAddr,
			Channel: 8,
			ID:      0x12345678,
			Decoded: &Data{Portnum: PortNumTextMessageApp, Payload: []byte("blocked")},
		})
	}()

	select {
	case <-clientConn.writePaused:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("MQTT Send did not enter Write")
	}

	// Canceling ctx must immediately close conn without deadlocking behind writeMu.
	cancel()

	select {
	case err := <-sendErr:
		if err == nil {
			t.Fatal("expected error from interrupted MQTT Send")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("MQTT Send remained blocked after context cancel")
	}

	select {
	case <-runDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("MQTTTransport.Run remained blocked after context cancel")
	}
}
