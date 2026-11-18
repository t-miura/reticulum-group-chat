package meshtastic

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestParsePSK(t *testing.T) {
	// "default" / "AQ==" -> 1-byte {0x01}, expanded to defaultPSK.
	for _, s := range []string{"default", "AQ==", "0x01", "simple1"} {
		raw, exp, err := ParsePSK(s)
		if err != nil {
			t.Fatalf("ParsePSK(%q): %v", s, err)
		}
		if !bytes.Equal(raw, []byte{0x01}) {
			t.Errorf("ParsePSK(%q) raw = %x, want 01", s, raw)
		}
		if !bytes.Equal(exp, defaultPSK[:]) {
			t.Errorf("ParsePSK(%q) exp = %x, want defaultPSK", s, exp)
		}
	}

	// simple2 increments last byte of defaultPSK by 1 (0x01 -> 0x02).
	_, exp2, err := ParsePSK("simple2")
	if err != nil {
		t.Fatalf("ParsePSK(simple2): %v", err)
	}
	if exp2[15] != defaultPSK[15]+1 {
		t.Errorf("simple2 last byte = 0x%02x, want 0x%02x", exp2[15], defaultPSK[15]+1)
	}

	// "none" and "" -> unencrypted.
	for _, s := range []string{"", "none", "NONE", "0x00"} {
		_, exp, err := ParsePSK(s)
		if err != nil {
			t.Fatalf("ParsePSK(%q): %v", s, err)
		}
		if len(exp) != 0 {
			t.Errorf("ParsePSK(%q) expanded = %x, want nil", s, exp)
		}
	}

	// 16-byte AES-128 and 32-byte AES-256 keys.
	k16 := bytes.Repeat([]byte{0x42}, 16)
	_, exp16, err := ParsePSK(base64.StdEncoding.EncodeToString(k16))
	if err != nil || !bytes.Equal(exp16, k16) {
		t.Fatalf("16-byte base64 key failed: exp=%x err=%v", exp16, err)
	}
	k32 := bytes.Repeat([]byte{0x99}, 32)
	_, exp32, err := ParsePSK("0x" + hex.EncodeToString(k32))
	if err != nil || !bytes.Equal(exp32, k32) {
		t.Fatalf("32-byte hex key failed: exp=%x err=%v", exp32, err)
	}

	// Invalid 5-byte key rejected.
	if _, _, err := ParsePSK("0x0102030405"); err == nil {
		t.Error("expected error for 5-byte PSK")
	}
}

func TestChannelHashDefaultLongFast(t *testing.T) {
	// Known Meshtastic test vector: LongFast with default PSK (AQ==) has hash 8.
	_, exp, err := ParsePSK("AQ==")
	if err != nil {
		t.Fatal(err)
	}
	if h := ChannelHash("LongFast", exp); h != 8 {
		t.Errorf("ChannelHash(LongFast, AQ==) = %d, want 8", h)
	}
}

func TestCryptPacketRoundTripAES128And256(t *testing.T) {
	payload := (&Data{
		Portnum: PortNumTextMessageApp,
		Payload: []byte("Testing AES-CTR Meshtastic encryption!"),
	}).Marshal()

	for _, key := range [][]byte{
		defaultPSK[:],
		bytes.Repeat([]byte{0xAB}, 32),
		nil,
	} {
		enc, err := CryptPacket(payload, 0x12345678, 0x9abcdef0, key)
		if err != nil {
			t.Fatalf("encrypt keylen=%d: %v", len(key), err)
		}
		if len(key) > 0 && bytes.Equal(enc, payload) {
			t.Fatalf("keylen=%d ciphertext equals plaintext", len(key))
		}
		dec, err := CryptPacket(enc, 0x12345678, 0x9abcdef0, key)
		if err != nil {
			t.Fatalf("decrypt keylen=%d: %v", len(key), err)
		}
		if !bytes.Equal(dec, payload) {
			t.Fatalf("keylen=%d round-trip mismatch", len(key))
		}
	}
}

func TestChannelURLRoundTrip(t *testing.T) {
	rawPSK := bytes.Repeat([]byte{0x5A}, 32)
	u := FormatChannelURL("ReticulumBridge", rawPSK)

	name, psk, err := ParseChannelURL(u)
	if err != nil {
		t.Fatalf("ParseChannelURL: %v", err)
	}
	if name != "ReticulumBridge" {
		t.Errorf("channel name = %q, want ReticulumBridge", name)
	}
	if !bytes.Equal(psk, rawPSK) {
		t.Errorf("psk = %x, want %x", psk, rawPSK)
	}

	// Default LongFast URL with empty name expands name to LongFast.
	defaultURL := FormatChannelURL("", []byte{0x01})
	name2, psk2, err := ParseChannelURL(defaultURL)
	if err != nil {
		t.Fatalf("ParseChannelURL default: %v", err)
	}
	if name2 != "LongFast" || !bytes.Equal(psk2, []byte{0x01}) {
		t.Errorf("default URL parsed (%q, %x)", name2, psk2)
	}
}
