package meshtastic

import (
	"bytes"
	"testing"
)

func TestProtoRoundTripMeshPacketAndEnvelope(t *testing.T) {
	in := &ServiceEnvelope{
		ChannelID: "LongFast",
		GatewayID: "!aabbccdd",
		Packet: &MeshPacket{
			From:     0x11223344,
			To:       BroadcastAddr,
			Channel:  8,
			ID:       0xdeadbeef,
			RxTime:   1700000000,
			RxSNR:    6.25,
			HopLimit: 3,
			WantAck:  true,
			RxRSSI:   -87,
			ViaMQTT:  true,
			HopStart: 3,
			Decoded: &Data{
				Portnum:      PortNumTextMessageApp,
				Payload:      []byte("hello mesh 👋"),
				WantResponse: true,
				Dest:         0x55667788,
				Source:       0x11223344,
				RequestID:    0x99aabbcc,
				ReplyID:      0x01020304,
				Emoji:        0x1f44d,
				Bitfield:     BitfieldOKToMQTT,
				HasBitfield:  true,
			},
		},
	}

	raw := in.Marshal()
	got, err := UnmarshalServiceEnvelope(raw)
	if err != nil {
		t.Fatalf("UnmarshalServiceEnvelope: %v", err)
	}
	if got.ChannelID != in.ChannelID || got.GatewayID != in.GatewayID {
		t.Fatalf("envelope ids mismatch: %+v", got)
	}
	gp := got.Packet
	ip := in.Packet
	if gp.From != ip.From || gp.To != ip.To || gp.Channel != ip.Channel || gp.ID != ip.ID {
		t.Fatalf("packet header mismatch: got=%+v want=%+v", gp, ip)
	}
	if gp.RxRSSI != -87 {
		t.Errorf("RxRSSI = %d, want -87", gp.RxRSSI)
	}
	if gp.RxSNR != 6.25 {
		t.Errorf("RxSNR = %v, want 6.25", gp.RxSNR)
	}
	if !gp.ViaMQTT || !gp.WantAck || gp.HopLimit != 3 || gp.HopStart != 3 {
		t.Errorf("packet flags mismatch: %+v", gp)
	}
	if gp.Decoded == nil || !bytes.Equal(gp.Decoded.Payload, ip.Decoded.Payload) {
		t.Fatalf("decoded payload mismatch: %+v", gp.Decoded)
	}
	if gp.Decoded.ReplyID != ip.Decoded.ReplyID || gp.Decoded.Emoji != ip.Decoded.Emoji || gp.Decoded.Bitfield != BitfieldOKToMQTT {
		t.Errorf("decoded fields mismatch: %+v", gp.Decoded)
	}
}

func TestProtoRoundTripUserAndChannelSet(t *testing.T) {
	u := &User{
		ID:        "!01020304",
		LongName:  "Alice Node",
		ShortName: "ALCE",
		HwModel:   HwModelPrivate,
		Role:      1,
	}
	gu, err := UnmarshalUser(u.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalUser: %v", err)
	}
	if *gu != *u {
		t.Errorf("User mismatch: got=%+v want=%+v", gu, u)
	}

	cs := &ChannelSet{
		Settings: []ChannelSettings{
			{
				PSK:             []byte{0x01},
				Name:            "LongFast",
				ID:              42,
				UplinkEnabled:   true,
				DownlinkEnabled: true,
			},
		},
	}
	gcs, err := UnmarshalChannelSet(cs.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalChannelSet: %v", err)
	}
	if len(gcs.Settings) != 1 || gcs.Settings[0].Name != "LongFast" || !bytes.Equal(gcs.Settings[0].PSK, []byte{0x01}) {
		t.Errorf("ChannelSet mismatch: %+v", gcs)
	}
}

func TestProtoSkipsUnknownFields(t *testing.T) {
	d := &Data{Portnum: PortNumTextMessageApp, Payload: []byte("ok")}
	raw := d.Marshal()
	// Append unknown varint field #99 and unknown bytes field #100.
	raw = appendVarintField(raw, 99, 12345)
	raw = appendBytesField(raw, 100, []byte("future-ext"))

	got, err := UnmarshalData(raw)
	if err != nil {
		t.Fatalf("UnmarshalData with unknown fields: %v", err)
	}
	if got.Portnum != PortNumTextMessageApp || string(got.Payload) != "ok" {
		t.Errorf("got=%+v", got)
	}
}

func TestProtoRoundTripStreamAPIMessages(t *testing.T) {
	// 1. ToRadio: WantConfigID, Packet, Disconnect, Heartbeat (nonce=0 MUST emit 0x3A 0x00).
	hbRaw := (&ToRadio{Heartbeat: &Heartbeat{}}).Marshal()
	if !bytes.Equal(hbRaw, []byte{0x3A, 0x00}) {
		t.Fatalf("Heartbeat(nonce=0) wire bytes = %x, want 3a00", hbRaw)
	}
	gotHB, err := UnmarshalToRadio(hbRaw)
	if err != nil || gotHB.Heartbeat == nil || gotHB.Heartbeat.Nonce != 0 {
		t.Fatalf("UnmarshalToRadio(Heartbeat): got=%+v err=%v", gotHB, err)
	}

	wantCfg := &ToRadio{WantConfigID: 0x12345678}
	gotWC, err := UnmarshalToRadio(wantCfg.Marshal())
	if err != nil || gotWC.WantConfigID != 0x12345678 {
		t.Fatalf("UnmarshalToRadio(WantConfigID): got=%+v err=%v", gotWC, err)
	}

	disc := &ToRadio{Disconnect: true}
	gotDisc, err := UnmarshalToRadio(disc.Marshal())
	if err != nil || !gotDisc.Disconnect {
		t.Fatalf("UnmarshalToRadio(Disconnect): got=%+v err=%v", gotDisc, err)
	}

	txPkt := &ToRadio{
		Packet: &MeshPacket{
			To:       BroadcastAddr,
			Channel:  2,
			ID:       0xabcdef01,
			HopLimit: 4,
			Priority: 64,
			Decoded: &Data{
				Portnum: PortNumTextMessageApp,
				Payload: []byte("via tcp"),
				ReplyID: 0x11112222,
				Emoji:   1,
			},
		},
	}
	gotTx, err := UnmarshalToRadio(txPkt.Marshal())
	if err != nil || gotTx.Packet == nil || gotTx.Packet.Channel != 2 || gotTx.Packet.Priority != 64 ||
		gotTx.Packet.Decoded == nil || string(gotTx.Packet.Decoded.Payload) != "via tcp" {
		t.Fatalf("UnmarshalToRadio(Packet): got=%+v err=%v", gotTx, err)
	}

	// 2. FromRadio variants: MyInfo, NodeInfo, Channel (with UseAEAD), RadioConfig, QueueStatus, ClientNotification, ConfigCompleteID, Rebooted.
	cases := []*FromRadio{
		{ID: 1, MyInfo: &MyNodeInfo{MyNodeNum: 0x43b5a120, RebootCount: 7, NodeDBCount: 42}},
		{ID: 2, NodeInfo: &NodeInfo{
			Num:       0x11223344,
			User:      &User{ID: "!11223344", ShortName: "ALCE", LongName: "Alice"},
			LastHeard: 1700001234,
			Channel:   1,
			ViaMQTT:   true,
		}},
		{ID: 3, Channel: &Channel{
			Index:       1,
			Role:        ChannelRoleSecondary,
			HasSettings: true,
			Settings: ChannelSettings{
				Name:            "JPCHAT",
				PSK:             []byte{0x01},
				UplinkEnabled:   true,
				DownlinkEnabled: true,
				UseAEAD:         true,
			},
		}},
		{ID: 4, Config: &RadioConfig{
			LoRa: &LoRaConfig{
				UsePreset:   true,
				ModemPreset: 4, // MEDIUM_FAST
				Region:      5, // JP
				HopLimit:    3,
			},
		}},
		{ID: 5, QueueStatus: &QueueStatus{Res: -1, Free: 15, Maxlen: 16, MeshPacketID: 0x55556666}},
		{ID: 6, ClientNotification: &ClientNotification{ReplyID: 0x77778888, Time: 1700000000, Level: 30, Message: "Duty cycle", Type: 4}},
		{ID: 7, ConfigCompleteID: 0x12345678, HasConfigCompleteID: true},
		{ID: 8, Rebooted: true},
	}

	for i, in := range cases {
		got, err := UnmarshalFromRadio(in.Marshal())
		if err != nil {
			t.Fatalf("case %d: UnmarshalFromRadio: %v", i, err)
		}
		if got.ID != in.ID {
			t.Errorf("case %d: ID = %d, want %d", i, got.ID, in.ID)
		}
		switch i {
		case 0:
			if got.MyInfo == nil || got.MyInfo.MyNodeNum != 0x43b5a120 || got.MyInfo.NodeDBCount != 42 {
				t.Errorf("MyInfo mismatch: %+v", got.MyInfo)
			}
		case 1:
			if got.NodeInfo == nil || got.NodeInfo.Num != 0x11223344 || got.NodeInfo.User == nil ||
				got.NodeInfo.User.ShortName != "ALCE" || got.NodeInfo.LastHeard != 1700001234 || !got.NodeInfo.ViaMQTT {
				t.Errorf("NodeInfo mismatch: %+v", got.NodeInfo)
			}
		case 2:
			if got.Channel == nil || got.Channel.Index != 1 || got.Channel.Role != ChannelRoleSecondary ||
				got.Channel.Settings.Name != "JPCHAT" || !got.Channel.Settings.UseAEAD {
				t.Errorf("Channel mismatch: %+v", got.Channel)
			}
		case 3:
			if got.Config == nil || got.Config.LoRa == nil || !got.Config.LoRa.UsePreset ||
				got.Config.LoRa.ModemPreset != 4 || got.Config.LoRa.HopLimit != 3 {
				t.Errorf("RadioConfig mismatch: %+v", got.Config)
			}
		case 4:
			if got.QueueStatus == nil || got.QueueStatus.Res != -1 || got.QueueStatus.Free != 15 ||
				got.QueueStatus.Maxlen != 16 || got.QueueStatus.MeshPacketID != 0x55556666 {
				t.Errorf("QueueStatus mismatch: %+v", got.QueueStatus)
			}
		case 5:
			if got.ClientNotification == nil || got.ClientNotification.Message != "Duty cycle" ||
				got.ClientNotification.Type != 4 || got.ClientNotification.ReplyID != 0x77778888 {
				t.Errorf("ClientNotification mismatch: %+v", got.ClientNotification)
			}
		case 6:
			if !got.HasConfigCompleteID || got.ConfigCompleteID != 0x12345678 {
				t.Errorf("ConfigCompleteID mismatch: %+v", got)
			}
		case 7:
			if !got.Rebooted {
				t.Errorf("Rebooted = false, want true")
			}
		}
	}

	// 3. Routing error reason decoding.
	rtRaw := appendVarintField(nil, 3, 29) // RATE_LIMIT_EXCEEDED
	rt, err := UnmarshalRouting(rtRaw)
	if err != nil || rt.ErrorReason != 29 {
		t.Errorf("UnmarshalRouting = %+v err=%v", rt, err)
	}

	// 4. ModemPresetDisplayName spot checks against DisplayFormatters.cpp.
	if got := ModemPresetDisplayName(0, true); got != "LongFast" {
		t.Errorf("preset 0 = %q, want LongFast", got)
	}
	if got := ModemPresetDisplayName(4, true); got != "MediumFast" {
		t.Errorf("preset 4 = %q, want MediumFast", got)
	}
	if got := ModemPresetDisplayName(7, true); got != "LongMod" {
		t.Errorf("preset 7 = %q, want LongMod", got)
	}
	if got := ModemPresetDisplayName(4, false); got != "Custom" {
		t.Errorf("usePreset=false = %q, want Custom", got)
	}
}
