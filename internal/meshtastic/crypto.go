package meshtastic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// defaultPSK is the canonical 16-byte Meshtastic default key (expanded from AQ== / 0x01).
var defaultPSK = [16]byte{
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
	0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
}

// ParsePSK parses a Meshtastic PSK string ("none", "default", "simple1".."simple10",
// "0x..." hex, or base64) and returns the raw PSK bytes alongside the expanded
// AES key (0, 16, or 32 bytes; nil means unencrypted).
func ParsePSK(s string) (rawPSK []byte, expandedKey []byte, err error) {
	trimmed := strings.TrimSpace(s)
	lower := strings.ToLower(trimmed)
	switch {
	case lower == "" || lower == "none":
		return nil, nil, nil
	case lower == "default":
		raw := []byte{0x01}
		exp, err := ExpandPSK(raw)
		return raw, exp, err
	case strings.HasPrefix(lower, "simple"):
		nStr := strings.TrimPrefix(lower, "simple")
		n, convErr := strconv.Atoi(nStr)
		if convErr != nil || n < 1 || n > 10 {
			return nil, nil, fmt.Errorf("meshtastic psk %q: simpleN must be simple1..simple10", s)
		}
		raw := []byte{byte(n)}
		exp, err := ExpandPSK(raw)
		return raw, exp, err
	case strings.HasPrefix(lower, "0x"):
		hexBody := strings.TrimPrefix(lower, "0x")
		if len(hexBody)%2 != 0 {
			return nil, nil, fmt.Errorf("meshtastic psk %q: hex string must have even length", s)
		}
		raw, err := hex.DecodeString(hexBody)
		if err != nil {
			return nil, nil, fmt.Errorf("meshtastic psk: invalid hex: %w", err)
		}
		exp, err := ExpandPSK(raw)
		return raw, exp, err
	default:
		raw, err := decodeBase64Flexible(trimmed)
		if err != nil {
			return nil, nil, fmt.Errorf("meshtastic psk: invalid base64: %w", err)
		}
		exp, err := ExpandPSK(raw)
		return raw, exp, err
	}
}

// ExpandPSK expands a Meshtastic raw PSK (0, 1, 16, or 32 bytes) into the AES
// cipher key used on the wire. A 1-byte non-zero PSK expands from defaultPSK
// with the last byte incremented by (psk[0] - 1).
func ExpandPSK(rawPSK []byte) ([]byte, error) {
	switch len(rawPSK) {
	case 0:
		return nil, nil
	case 1:
		if rawPSK[0] == 0 {
			return nil, nil
		}
		key := make([]byte, len(defaultPSK))
		copy(key, defaultPSK[:])
		key[len(key)-1] += rawPSK[0] - 1
		return key, nil
	case 16, 32:
		key := make([]byte, len(rawPSK))
		copy(key, rawPSK)
		return key, nil
	default:
		return nil, fmt.Errorf("meshtastic psk must be 0, 1, 16, or 32 bytes (got %d)", len(rawPSK))
	}
}

// ChannelHash computes the 8-bit Meshtastic channel hash:
// xorHash(channelName) ^ xorHash(expandedKey).
func ChannelHash(channelName string, expandedKey []byte) uint8 {
	return xorHash([]byte(channelName)) ^ xorHash(expandedKey)
}

func xorHash(b []byte) uint8 {
	var h uint8
	for _, v := range b {
		h ^= v
	}
	return h
}

// CryptPacket encrypts or decrypts a Meshtastic Data protobuf payload using
// AES-128/256-CTR with Meshtastic's 16-byte nonce:
// littleEndianUint64(packetID) || littleEndianUint32(fromNode) || 4 zero bytes.
// When expandedKey is empty, returns a plain copy of payload.
func CryptPacket(payload []byte, packetID, fromNode uint32, expandedKey []byte) ([]byte, error) {
	out := make([]byte, len(payload))
	if len(expandedKey) == 0 {
		copy(out, payload)
		return out, nil
	}
	block, err := aes.NewCipher(expandedKey)
	if err != nil {
		return nil, fmt.Errorf("meshtastic aes init: %w", err)
	}
	var nonce [16]byte
	binary.LittleEndian.PutUint64(nonce[0:8], uint64(packetID))
	binary.LittleEndian.PutUint32(nonce[8:12], fromNode)
	cipher.NewCTR(block, nonce[:]).XORKeyStream(out, payload)
	return out, nil
}

// ParseChannelURL extracts the primary channel name and raw PSK from a
// Meshtastic share URL (https://meshtastic.org/e/#... or meshtastic://...).
func ParseChannelURL(rawURL string) (channelName string, rawPSK []byte, err error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", nil, fmt.Errorf("empty channel URL")
	}
	var encoded string
	if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
		encoded = trimmed[idx+1:]
	} else {
		return "", nil, fmt.Errorf("meshtastic channel_url missing '#' payload")
	}
	if encoded == "" {
		return "", nil, fmt.Errorf("meshtastic channel_url has empty '#' payload")
	}
	raw, err := decodeBase64Flexible(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("decode channel_url payload: %w", err)
	}
	cs, err := UnmarshalChannelSet(raw)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal ChannelSet: %w", err)
	}
	if len(cs.Settings) == 0 {
		return "", nil, fmt.Errorf("channel_url contains no channel settings")
	}
	primary := cs.Settings[0]
	name := primary.Name
	if name == "" && len(primary.PSK) == 1 && primary.PSK[0] == 1 {
		name = "LongFast"
	}
	return name, primary.PSK, nil
}

// FormatChannelURL builds a shareable https://meshtastic.org/e/#... URL for the
// given channel name and raw PSK.
func FormatChannelURL(channelName string, rawPSK []byte) string {
	cs := &ChannelSet{
		Settings: []ChannelSettings{
			{
				PSK:             rawPSK,
				Name:            channelName,
				UplinkEnabled:   true,
				DownlinkEnabled: true,
			},
		},
	}
	return "https://meshtastic.org/e/#" + base64.RawURLEncoding.EncodeToString(cs.Marshal())
}

func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
