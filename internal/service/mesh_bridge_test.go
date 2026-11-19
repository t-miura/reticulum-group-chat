package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/commands"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/meshtastic"
)

type svcMeshMockTransport struct {
	mu      sync.Mutex
	onRx    func(*meshtastic.MeshPacket)
	sent    []*meshtastic.MeshPacket
	sentCh  chan *meshtastic.MeshPacket
	readyCh chan struct{}
}

func newSvcMeshMockTransport() *svcMeshMockTransport {
	return &svcMeshMockTransport{
		sentCh:  make(chan *meshtastic.MeshPacket, 32),
		readyCh: make(chan struct{}),
	}
}

func (m *svcMeshMockTransport) Name() string { return "mock" }

func (m *svcMeshMockTransport) Run(ctx context.Context, onPacket func(*meshtastic.MeshPacket)) error {
	m.mu.Lock()
	m.onRx = onPacket
	select {
	case <-m.readyCh:
	default:
		close(m.readyCh)
	}
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (m *svcMeshMockTransport) Send(_ context.Context, pkt *meshtastic.MeshPacket) error {
	m.mu.Lock()
	m.sent = append(m.sent, pkt)
	m.mu.Unlock()
	select {
	case m.sentCh <- pkt:
	default:
	}
	return nil
}

func (m *svcMeshMockTransport) inject(pkt *meshtastic.MeshPacket) {
	m.mu.Lock()
	cb := m.onRx
	m.mu.Unlock()
	if cb != nil {
		cb(pkt)
	}
}

func (m *svcMeshMockTransport) waitSent(t *testing.T, key []byte) (*meshtastic.MeshPacket, *meshtastic.Data) {
	t.Helper()
	select {
	case pkt := <-m.sentCh:
		var data *meshtastic.Data
		var err error
		if pkt.Decoded != nil {
			data = pkt.Decoded
		} else {
			plain, cerr := meshtastic.CryptPacket(pkt.Encrypted, pkt.ID, pkt.From, key)
			if cerr != nil {
				t.Fatalf("decrypt outbound mesh pkt: %v", cerr)
			}
			data, err = meshtastic.UnmarshalData(plain)
			if err != nil {
				t.Fatalf("unmarshal outbound mesh Data: %v", err)
			}
		}
		return pkt, data
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound Meshtastic packet")
		return nil, nil
	}
}

func newTestServiceWithMesh(t *testing.T, adminHex string) (*Service, *svcMeshMockTransport, *fakeSender, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	src := fmt.Sprintf(`admins = [%q]

[service]
display_name = "Mesh Chat"
identity_path = %q
state_path = %q
history_path = %q

[meshtastic]
enabled = true
channel_name = "LongFast"
psk = "AQ=="
short_name = "RNS"
nodeinfo_interval = "0"
chunk_delay = "0s"
max_chunks = 3

[meshtastic.udp]
enabled = true
addr = "127.0.0.1:0"
`,
		adminHex,
		filepath.Join(dir, "identity"),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "history.json"),
	)
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	fs := &fakeSender{}
	svc.outbound = newOutboundQueue(fs, nil, svc.logger)
	svc.outbound.SetIDMap(svc.idmap)

	tr := newSvcMeshMockTransport()
	svc.mesh.SetTransports(tr)

	ctx, cancel := context.WithCancel(context.Background())
	meshDone := make(chan struct{})
	go func() {
		defer close(meshDone)
		svc.mesh.Run(ctx)
	}()
	select {
	case <-tr.readyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("mock mesh transport not ready")
	}

	cleanup := func() {
		cancel()
		<-meshDone
		if svc.instanceUnlock != nil {
			svc.instanceUnlock()
		}
	}
	return svc, tr, fs, cleanup
}

func encryptTestMeshPacket(t *testing.T, svc *Service, from, to, pktID uint32, d *meshtastic.Data) *meshtastic.MeshPacket {
	t.Helper()
	enc, err := meshtastic.CryptPacket(d.Marshal(), pktID, from, svc.cfg.Meshtastic.ExpandedKey)
	if err != nil {
		t.Fatal(err)
	}
	return &meshtastic.MeshPacket{
		From:      from,
		To:        to,
		Channel:   uint32(svc.mesh.ChannelHash()),
		ID:        pktID,
		Encrypted: enc,
	}
}

func TestMeshBridgeBidirectionalTextChunkingAndCommands(t *testing.T) {
	aliceID, aliceDest := newSender(t)
	aliceHex := hex.EncodeToString(aliceDest)
	_, bobDest := newSender(t)

	svc, tr, fs, cancel := newTestServiceWithMesh(t, aliceHex)
	defer cancel()

	if _, err := svc.roster.AddOrUpdate(aliceDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	_ = svc.roster.SetNickname(aliceHex, "alice")
	if _, err := svc.roster.AddOrUpdate(bobDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	bobHex := hex.EncodeToString(bobDest)
	_ = svc.roster.SetNickname(bobHex, "bob")

	key := svc.cfg.Meshtastic.ExpandedKey

	// 1. LXMF -> Meshtastic short text.
	svc.onLXMFReceived(inbound(t, svc, aliceID, aliceDest, "hello mesh"))
	_, data := tr.waitSent(t, key)
	if string(data.Payload) != "[alice] hello mesh" {
		t.Errorf("mesh outbound = %q, want %q", string(data.Payload), "[alice] hello mesh")
	}

	// 2. LXMF -> Meshtastic long message chunking (>220 bytes -> 2 chunks).
	longMsg := strings.Repeat("word ", 55) // 275 bytes
	svc.onLXMFReceived(inbound(t, svc, aliceID, aliceDest, strings.TrimSpace(longMsg)))
	_, c1 := tr.waitSent(t, key)
	_, c2 := tr.waitSent(t, key)
	if !strings.HasSuffix(string(c1.Payload), "(1/2)") || !strings.HasSuffix(string(c2.Payload), "(2/2)") {
		t.Errorf("expected (1/2) and (2/2) chunks, got %q and %q", string(c1.Payload), string(c2.Payload))
	}

	// 3. LXMF image-only message -> text attachment notice on Meshtastic.
	svc.onLXMFReceived(inboundWithFields(t, svc, aliceID, aliceDest, "", map[any]any{
		6: []any{"jpg", []byte{0xff, 0xd8, 0xff}},
	}))
	_, att := tr.waitSent(t, key)
	if string(att.Payload) != "[alice] [sent an attachment on LXMF]" {
		t.Errorf("attachment notice = %q", string(att.Payload))
	}

	// 4. Meshtastic NODEINFO + text -> LXMF fanout + history.
	meshPeer := uint32(0x12345678)
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, svc.mesh.BridgeNodeID(), 7001, &meshtastic.Data{
		Portnum: meshtastic.PortNumNodeInfoApp,
		Payload: (&meshtastic.User{ID: "!12345678", ShortName: "MESH", LongName: "Mesh Node"}).Marshal(),
	}))
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, meshtastic.BroadcastAddr, 7002, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("hi reticulum"),
	}))

	// Drain LXMF outbound queue.
	svc.outbound.processOnce(context.Background())

	fs.mu.Lock()
	var sawMeshMsg bool
	for _, body := range fs.sendCalls {
		if string(body) == "[M:MESH] hi reticulum" {
			sawMeshMsg = true
		}
	}
	beforeCalls := len(fs.sendCalls)
	fs.mu.Unlock()
	if !sawMeshMsg {
		t.Fatalf("LXMF roster did not receive Meshtastic message; calls=%q", fs.sendCalls)
	}

	// Verify history recorded the Meshtastic message.
	entries := svc.history.SinceOldest(time.Time{})
	if len(entries) == 0 || entries[len(entries)-1].SenderNick != "M:MESH" || entries[len(entries)-1].Content != "hi reticulum" {
		t.Errorf("history missing Meshtastic entry: %+v", entries)
	}

	// 5. Slash command from Meshtastic must be ignored (no LXMF forward, no RF reply).
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, meshtastic.BroadcastAddr, 7003, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("/users"),
	}))
	svc.outbound.processOnce(context.Background())
	fs.mu.Lock()
	afterCalls := len(fs.sendCalls)
	fs.mu.Unlock()
	if afterCalls != beforeCalls {
		t.Errorf("slash command from Meshtastic leaked to LXMF outbound (%d -> %d)", beforeCalls, afterCalls)
	}
	select {
	case extra := <-tr.sentCh:
		t.Errorf("slash command from Meshtastic triggered RF reply: %+v", extra)
	default:
	}

	// 6. /mesh visibility + /ban !hex moderation.
	if reply := svc.dispatcher.Dispatch(bobHex, commands.Parse("/mesh")); strings.Contains(reply, "PSK:") || !strings.Contains(reply, "#LongFast") {
		t.Errorf("non-admin /mesh unexpected: %q", reply)
	}
	if reply := svc.dispatcher.Dispatch(aliceHex, commands.Parse("/mesh")); !strings.Contains(reply, "PSK: AQ==") {
		t.Errorf("admin /mesh missing PSK: %q", reply)
	}
	if reply := svc.dispatcher.Dispatch(aliceHex, commands.Parse("/ban !12345678")); !strings.Contains(reply, "Banned Meshtastic node") {
		t.Errorf("/ban !12345678 = %q", reply)
	}
	if !svc.mesh.NodeDB().IsBanned(meshPeer) {
		t.Error("meshPeer not marked banned in NodeDB")
	}
	if reply := svc.dispatcher.Dispatch(aliceHex, commands.Parse("/unban !12345678")); !strings.Contains(reply, "Unbanned Meshtastic node") {
		t.Errorf("/unban !12345678 = %q", reply)
	}
	if svc.mesh.NodeDB().IsBanned(meshPeer) {
		t.Error("meshPeer still banned after /unban")
	}
}

func TestMeshBridgeBidirectionalRepliesAndReactions(t *testing.T) {
	aliceID, aliceDest := newSender(t)
	aliceHex := hex.EncodeToString(aliceDest)
	bobID, bobDest := newSender(t)
	bobHex := hex.EncodeToString(bobDest)

	svc, tr, fs, cancel := newTestServiceWithMesh(t, aliceHex)
	defer cancel()

	if _, err := svc.roster.AddOrUpdate(aliceDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	_ = svc.roster.SetNickname(aliceHex, "alice")
	if _, err := svc.roster.AddOrUpdate(bobDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	_ = svc.roster.SetNickname(bobHex, "bob")

	key := svc.cfg.Meshtastic.ExpandedKey

	// --- Case A: LXMF -> Meshtastic -> Meshtastic reply & reaction back to LXMF ---
	lxmfMsg := inbound(t, svc, aliceID, aliceDest, "target from lxmf")
	svc.onLXMFReceived(lxmfMsg)
	svc.outbound.processOnce(context.Background())

	outPkt, _ := tr.waitSent(t, key)

	// Capture Bob's registered LXMF message_id view for lxmfMsg.
	fs.mu.Lock()
	var bobView []byte
	for i, r := range fs.sendRecipients {
		if bytes.Equal(r, bobDest) && string(fs.sendCalls[i]) == "[alice] target from lxmf" {
			bobView = make([]byte, 32)
			bobView[0] = r[0]
			bobView[1] = byte(i + 1)
		}
	}
	fs.mu.Unlock()
	if len(bobView) != 32 {
		t.Fatal("failed to locate Bob's fanout send")
	}
	b := svc.idmap.LookupMeshID(outPkt.ID)
	if b == nil {
		t.Fatal("idmap missing Meshtastic packet ID for LXMF outbound")
	}
	bobRegisteredHex, ok := b.ViewFor(bobHex)
	if !ok {
		t.Fatal("idmap missing Bob's view for LXMF outbound")
	}
	aliceRegisteredHex, ok := b.ViewFor(aliceHex)
	if !ok {
		t.Fatal("idmap missing Alice's sender view")
	}

	// Meshtastic peer replies to outPkt.ID and reacts to outPkt.ID.
	meshPeer := uint32(0xdeadbeef)
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, meshtastic.BroadcastAddr, 8001, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("mesh reply"),
		ReplyID: outPkt.ID,
	}))
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, meshtastic.BroadcastAddr, 8002, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("🔥"),
		ReplyID: outPkt.ID,
		Emoji:   1,
	}))
	svc.outbound.processOnce(context.Background())

	// Verify both Alice and Bob got rewritten FIELD_REPLY_TO + FIELD_REPLY_QUOTE and FIELD_REACTION + originator-identity.
	fs.mu.Lock()
	var sawAliceReply, sawBobReaction bool
	for i, r := range fs.sendRecipients {
		fields := fs.sendFields[i]
		body := string(fs.sendCalls[i])
		if bytes.Equal(r, aliceDest) && strings.Contains(body, "mesh reply") {
			if raw, ok := fields[fieldReplyTo].([]byte); ok && hex.EncodeToString(raw) == aliceRegisteredHex {
				if q, ok := fields[fieldReplyQuote].([]byte); ok && string(q) == "[alice] target from lxmf" {
					sawAliceReply = true
				}
			}
		}
		if bytes.Equal(r, bobDest) && body == "" {
			if rm, ok := fields[fieldReaction].(map[any]any); ok {
				if raw, ok := rm[targetIdx].([]byte); ok && hex.EncodeToString(raw) == bobRegisteredHex {
					if string(rm[0x01].([]byte)) == "🔥" &&
						fields[fieldCustomType] == originatorIdentityType &&
						bytes.Equal(fields[fieldCustomData].([]byte), meshtastic.SyntheticLXMFHash(meshPeer)) {
						sawBobReaction = true
					}
				}
			}
		}
	}
	fs.mu.Unlock()
	if !sawAliceReply {
		t.Error("Alice did not receive Meshtastic reply bound to her view with quote")
	}
	if !sawBobReaction {
		t.Error("Bob did not receive Meshtastic tap-back reaction bound to his view with originator stamp")
	}

	// --- Case B: Meshtastic -> LXMF -> LXMF reply & reaction back to Meshtastic ---
	tr.inject(encryptTestMeshPacket(t, svc, meshPeer, meshtastic.BroadcastAddr, 9001, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("mesh origin"),
	}))
	svc.outbound.processOnce(context.Background())

	mb := svc.idmap.LookupMeshID(9001)
	if mb == nil {
		t.Fatal("idmap missing bubble for Meshtastic origin 9001")
	}
	bobMeshViewHex, ok := mb.ViewFor(bobHex)
	if !ok {
		t.Fatal("idmap missing Bob's view for Meshtastic origin 9001")
	}
	bobMeshViewBytes, _ := hex.DecodeString(bobMeshViewHex)

	// Bob replies and reacts to 9001 via LXMF.
	svc.onLXMFReceived(inboundWithFields(t, svc, bobID, bobDest, "lxmf reply to mesh", map[any]any{
		fieldReplyTo: bobMeshViewBytes,
	}))
	_, replyMeshData := tr.waitSent(t, key)
	if replyMeshData.ReplyID != 9001 || string(replyMeshData.Payload) != "[bob] lxmf reply to mesh" {
		t.Errorf("LXMF->Mesh reply = %+v (payload=%q), want reply_id=9001", replyMeshData, string(replyMeshData.Payload))
	}

	svc.onLXMFReceived(inboundWithFields(t, svc, bobID, bobDest, "", map[any]any{
		fieldReaction: map[any]any{
			targetIdx: bobMeshViewBytes,
			0x01:      []byte("👍"),
		},
	}))
	_, reactMeshData := tr.waitSent(t, key)
	if reactMeshData.ReplyID != 9001 || reactMeshData.Emoji != 1 || string(reactMeshData.Payload) != "👍" {
		t.Errorf("LXMF->Mesh reaction = %+v (payload=%q), want emoji=1 reply_id=9001 👍", reactMeshData, string(reactMeshData.Payload))
	}

	// FIELD_COMMENT (0x41) targeting 9001 also preserves ReplyID on Meshtastic.
	svc.onLXMFReceived(inboundWithFields(t, svc, bobID, bobDest, "comment on mesh", map[any]any{
		fieldComment: map[any]any{
			targetIdx: bobMeshViewBytes,
		},
	}))
	_, commentMeshData := tr.waitSent(t, key)
	if commentMeshData.ReplyID != 9001 || string(commentMeshData.Payload) != "[bob] comment on mesh" {
		t.Errorf("LXMF->Mesh comment = %+v (payload=%q), want reply_id=9001", commentMeshData, string(commentMeshData.Payload))
	}
}

func TestMeshInboundRespectsMaxInboundChars(t *testing.T) {
	_, aliceDest := newSender(t)
	aliceHex := hex.EncodeToString(aliceDest)

	svc, tr, fs, cancel := newTestServiceWithMesh(t, aliceHex)
	defer cancel()

	svc.cfg.Service.MaxInboundChars = 10
	if _, err := svc.roster.AddOrUpdate(aliceDest, svc.now()); err != nil {
		t.Fatal(err)
	}

	tr.inject(encryptTestMeshPacket(t, svc, 0x11223344, meshtastic.BroadcastAddr, 9501, &meshtastic.Data{
		Portnum: meshtastic.PortNumTextMessageApp,
		Payload: []byte("1234567890abcdef"),
	}))
	svc.outbound.processOnce(context.Background())

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.sendCalls) != 1 || string(fs.sendCalls[0]) != "[M:!3344] 123456789…" {
		t.Errorf("truncated mesh forward = %q, want [M:!3344] 123456789…", fs.sendCalls)
	}
}

func writeTestStreamFrame(w io.Writer, payload []byte) error {
	hdr := [4]byte{0x94, 0xC3, byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readTestStreamFrame(r *bufio.Reader) ([]byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != 0x94 {
			continue
		}
		b2, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b2 != 0xC3 {
			continue
		}
		var lb [2]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
}

func TestServiceExternalMeshtasticdTCPIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock meshtasticd: %v", err)
	}
	defer ln.Close()

	txCh := make(chan *meshtastic.MeshPacket, 8)
	pushCh := make(chan *meshtastic.FromRadio, 8)

	// Minimal mock meshtasticd over real loopback TCP.
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		var wmu sync.Mutex
		sendFR := func(fr *meshtastic.FromRadio) {
			wmu.Lock()
			defer wmu.Unlock()
			_ = writeTestStreamFrame(conn, fr.Marshal())
		}
		done := make(chan struct{})
		defer close(done)
		go func() {
			for {
				select {
				case <-done:
					return
				case fr := <-pushCh:
					sendFR(fr)
				}
			}
		}()

		br := bufio.NewReader(conn)
		for {
			raw, rerr := readTestStreamFrame(br)
			if rerr != nil {
				return
			}
			tr, uerr := meshtastic.UnmarshalToRadio(raw)
			if uerr != nil {
				continue
			}
			switch {
			case tr.WantConfigID != 0:
				sendFR(&meshtastic.FromRadio{MyInfo: &meshtastic.MyNodeInfo{MyNodeNum: 0x55aa1122}})
				sendFR(&meshtastic.FromRadio{NodeInfo: &meshtastic.NodeInfo{
					Num:  0x55aa1122,
					User: &meshtastic.User{ID: "!55aa1122", ShortName: "DAEM", LongName: "Local Meshtasticd"},
				}})
				sendFR(&meshtastic.FromRadio{Channel: &meshtastic.Channel{
					Index: 0, Role: meshtastic.ChannelRolePrimary, HasSettings: true,
					Settings: meshtastic.ChannelSettings{Name: "", PSK: []byte{0x01}},
				}})
				sendFR(&meshtastic.FromRadio{Channel: &meshtastic.Channel{
					Index: 1, Role: meshtastic.ChannelRoleSecondary, HasSettings: true,
					Settings: meshtastic.ChannelSettings{Name: "RFBridge", PSK: []byte{0x01}},
				}})
				sendFR(&meshtastic.FromRadio{Config: &meshtastic.RadioConfig{
					LoRa: &meshtastic.LoRaConfig{UsePreset: true, ModemPreset: 0, HopLimit: 3},
				}})
				sendFR(&meshtastic.FromRadio{NodeInfo: &meshtastic.NodeInfo{
					Num:       0x778899aa,
					User:      &meshtastic.User{ID: "!778899aa", ShortName: "RF01", LongName: "RF Radio 1"},
					LastHeard: uint32(time.Now().Unix()),
				}})
				sendFR(&meshtastic.FromRadio{ConfigCompleteID: tr.WantConfigID, HasConfigCompleteID: true})
			case tr.Packet != nil:
				txCh <- tr.Packet
				sendFR(&meshtastic.FromRadio{QueueStatus: &meshtastic.QueueStatus{Res: 0, Free: 15, Maxlen: 16, MeshPacketID: tr.Packet.ID}})
			case tr.Disconnect:
				return
			}
		}
	}()

	aliceID, aliceDest := newSender(t)
	aliceHex := hex.EncodeToString(aliceDest)
	_, bobDest := newSender(t)
	bobHex := hex.EncodeToString(bobDest)

	dir := t.TempDir()
	// Note: channel_name is omitted; channel_index = 1 selects "RFBridge" from the node!
	src := fmt.Sprintf(`admins = [%q]

[service]
display_name = "External Mesh Chat"
identity_path = %q
state_path = %q
history_path = %q

[meshtastic]
enabled = true
mode = "external"
chunk_delay = "0s"

[meshtastic.tcp]
addr = %q
channel_index = 1
`,
		aliceHex,
		filepath.Join(dir, "identity"),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "history.json"),
		ln.Addr().String(),
	)
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	fs := &fakeSender{}
	svc.outbound = newOutboundQueue(fs, nil, svc.logger)
	svc.outbound.SetIDMap(svc.idmap)

	ctx, cancel := context.WithCancel(context.Background())
	meshDone := make(chan struct{})
	go func() {
		defer close(meshDone)
		svc.mesh.Run(ctx)
	}()
	defer func() {
		cancel()
		<-meshDone
		if svc.instanceUnlock != nil {
			svc.instanceUnlock()
		}
	}()

	select {
	case <-svc.mesh.TCPTransport().Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("external TCP bridge did not complete handshake")
	}

	if _, err := svc.roster.AddOrUpdate(aliceDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	_ = svc.roster.SetNickname(aliceHex, "alice")
	if _, err := svc.roster.AddOrUpdate(bobDest, svc.now()); err != nil {
		t.Fatal(err)
	}
	_ = svc.roster.SetNickname(bobHex, "bob")

	// 1. /info reflects the channel name learned dynamically from the external node (#RFBridge).
	if info := svc.dispatcher.Dispatch(bobHex, commands.Parse("/info")); !strings.Contains(info, "Meshtastic: #RFBridge (/mesh)") {
		t.Errorf("/info = %q, want learned #RFBridge", info)
	}

	// 2. /mesh hides PSK for members, reveals external node's channel PSK for admins.
	if st := svc.dispatcher.Dispatch(bobHex, commands.Parse("/mesh")); strings.Contains(st, "PSK:") || !strings.Contains(st, "!55aa1122") || !strings.Contains(st, "mode external") {
		t.Errorf("member /mesh unexpected:\n%s", st)
	}
	if st := svc.dispatcher.Dispatch(aliceHex, commands.Parse("/mesh")); !strings.Contains(st, "PSK: AQ==") || !strings.Contains(st, "#RFBridge") {
		t.Errorf("admin /mesh unexpected:\n%s", st)
	}

	// 3. LXMF -> external Meshtastic node on channel index 1.
	svc.onLXMFReceived(inbound(t, svc, aliceID, aliceDest, "hello via meshtasticd"))
	select {
	case pkt := <-txCh:
		if pkt.Channel != 1 || pkt.To != meshtastic.BroadcastAddr || pkt.Decoded == nil ||
			string(pkt.Decoded.Payload) != "[alice] hello via meshtasticd" {
			t.Errorf("outbound external pkt = %+v", pkt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for outbound packet on mock meshtasticd")
	}

	// 4. External Meshtastic RF peer (attributed via handshake-seeded NodeDB!) -> LXMF roster.
	pushCh <- &meshtastic.FromRadio{
		Packet: &meshtastic.MeshPacket{
			From:    0x778899aa,
			To:      meshtastic.BroadcastAddr,
			Channel: 1,
			ID:      0xaa001122,
			Decoded: &meshtastic.Data{
				Portnum: meshtastic.PortNumTextMessageApp,
				Payload: []byte("roger from lora rf"),
			},
		},
	}

	deadline := time.Now().Add(2 * time.Second)
	var sawRF bool
	for time.Now().Before(deadline) {
		svc.outbound.processOnce(context.Background())
		fs.mu.Lock()
		for _, body := range fs.sendCalls {
			if string(body) == "[M:RF01] roger from lora rf" {
				sawRF = true
			}
		}
		fs.mu.Unlock()
		if sawRF {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawRF {
		t.Fatalf("LXMF roster did not receive RF message; sendCalls=%q", fs.sendCalls)
	}
}
