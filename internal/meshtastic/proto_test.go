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
