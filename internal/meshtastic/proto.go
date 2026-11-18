// Package meshtastic implements a wire-compatible Meshtastic channel bridge
// (protobuf codec, PSK AES-CTR encryption, UDP multicast, MQTT v3.1.1, node DB,
// and chunking) using only the Go standard library.
package meshtastic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// BroadcastAddr is the Meshtastic broadcast destination node ID (0xFFFFFFFF).
const BroadcastAddr uint32 = 0xFFFFFFFF

// PortNum identifies the Meshtastic application payload type inside Data.
const (
	PortNumUnknown        uint32 = 0
	PortNumTextMessageApp uint32 = 1
	PortNumNodeInfoApp    uint32 = 4
)

// HwModelPrivate is meshtastic.HardwareModel_PRIVATE_HW (255).
const HwModelPrivate uint32 = 255

// BitfieldOKToMQTT is bit 0 of Data.bitfield (ok_to_mqtt).
const BitfieldOKToMQTT uint32 = 0x01

var (
	errTruncatedProto = errors.New("meshtastic proto: truncated buffer")
	errInvalidVarint  = errors.New("meshtastic proto: varint overflow")
	errInvalidWire    = errors.New("meshtastic proto: invalid wire type")
)

// Data corresponds to meshtastic.Data (mesh.proto).
type Data struct {
	Portnum      uint32
	Payload      []byte
	WantResponse bool
	Dest         uint32
	Source       uint32
	RequestID    uint32
	ReplyID      uint32
	Emoji        uint32
	Bitfield     uint32
	HasBitfield  bool
}

// User corresponds to meshtastic.User (mesh.proto), carried in NODEINFO_APP.
type User struct {
	ID        string
	LongName  string
	ShortName string
	HwModel   uint32
	Role      uint32
}

// MeshPacket corresponds to meshtastic.MeshPacket (mesh.proto).
type MeshPacket struct {
	From      uint32
	To        uint32
	Channel   uint32
	Decoded   *Data
	Encrypted []byte
	ID        uint32
	RxTime    uint32
	RxSNR     float32
	HopLimit  uint32
	WantAck   bool
	RxRSSI    int32
	ViaMQTT   bool
	HopStart  uint32
}

// ServiceEnvelope corresponds to meshtastic.ServiceEnvelope (mqtt.proto).
type ServiceEnvelope struct {
	Packet    *MeshPacket
	ChannelID string
	GatewayID string
}

// ChannelSettings corresponds to meshtastic.ChannelSettings (channel.proto).
type ChannelSettings struct {
	PSK             []byte
	Name            string
	ID              uint32
	UplinkEnabled   bool
	DownlinkEnabled bool
}

// ChannelSet corresponds to meshtastic.ChannelSet (apponly.proto).
type ChannelSet struct {
	Settings []ChannelSettings
}

// Marshal encodes Data into protobuf wire format.
func (d *Data) Marshal() []byte {
	var b []byte
	if d.Portnum != 0 {
		b = appendVarintField(b, 1, uint64(d.Portnum))
	}
	if len(d.Payload) > 0 {
		b = appendBytesField(b, 2, d.Payload)
	}
	if d.WantResponse {
		b = appendVarintField(b, 3, 1)
	}
	if d.Dest != 0 {
		b = appendFixed32Field(b, 4, d.Dest)
	}
	if d.Source != 0 {
		b = appendFixed32Field(b, 5, d.Source)
	}
	if d.RequestID != 0 {
		b = appendFixed32Field(b, 6, d.RequestID)
	}
	if d.ReplyID != 0 {
		b = appendFixed32Field(b, 7, d.ReplyID)
	}
	if d.Emoji != 0 {
		b = appendFixed32Field(b, 8, d.Emoji)
	}
	if d.HasBitfield || d.Bitfield != 0 {
		b = appendVarintField(b, 9, uint64(d.Bitfield))
	}
	return b
}

// UnmarshalData decodes a protobuf-encoded Data message.
func UnmarshalData(buf []byte) (*Data, error) {
	d := &Data{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Portnum = uint32(v)
			i += m
		case 2:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Payload = append([]byte(nil), v...)
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			d.WantResponse = v != 0
			i += m
		case 4:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Dest = v
			i += m
		case 5:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Source = v
			i += m
		case 6:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			d.RequestID = v
			i += m
		case 7:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			d.ReplyID = v
			i += m
		case 8:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Emoji = v
			i += m
		case 9:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			d.Bitfield = uint32(v)
			d.HasBitfield = true
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return d, nil
}

// Marshal encodes User into protobuf wire format.
func (u *User) Marshal() []byte {
	var b []byte
	if u.ID != "" {
		b = appendBytesField(b, 1, []byte(u.ID))
	}
	if u.LongName != "" {
		b = appendBytesField(b, 2, []byte(u.LongName))
	}
	if u.ShortName != "" {
		b = appendBytesField(b, 3, []byte(u.ShortName))
	}
	if u.HwModel != 0 {
		b = appendVarintField(b, 5, uint64(u.HwModel))
	}
	if u.Role != 0 {
		b = appendVarintField(b, 7, uint64(u.Role))
	}
	return b
}

// UnmarshalUser decodes a protobuf-encoded User message.
func UnmarshalUser(buf []byte) (*User, error) {
	u := &User{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			u.ID = string(v)
			i += m
		case 2:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			u.LongName = string(v)
			i += m
		case 3:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			u.ShortName = string(v)
			i += m
		case 5:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			u.HwModel = uint32(v)
			i += m
		case 7:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			u.Role = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return u, nil
}

// Marshal encodes MeshPacket into protobuf wire format.
func (p *MeshPacket) Marshal() []byte {
	var b []byte
	if p.From != 0 {
		b = appendFixed32Field(b, 1, p.From)
	}
	if p.To != 0 {
		b = appendFixed32Field(b, 2, p.To)
	}
	if p.Channel != 0 {
		b = appendVarintField(b, 3, uint64(p.Channel))
	}
	if p.Decoded != nil {
		b = appendBytesField(b, 4, p.Decoded.Marshal())
	} else if len(p.Encrypted) > 0 {
		b = appendBytesField(b, 5, p.Encrypted)
	}
	if p.ID != 0 {
		b = appendFixed32Field(b, 6, p.ID)
	}
	if p.RxTime != 0 {
		b = appendFixed32Field(b, 7, p.RxTime)
	}
	if p.RxSNR != 0 {
		b = appendFixed32Field(b, 8, math.Float32bits(p.RxSNR))
	}
	if p.HopLimit != 0 {
		b = appendVarintField(b, 9, uint64(p.HopLimit))
	}
	if p.WantAck {
		b = appendVarintField(b, 10, 1)
	}
	if p.RxRSSI != 0 {
		b = appendVarintField(b, 12, uint64(int64(p.RxRSSI)))
	}
	if p.ViaMQTT {
		b = appendVarintField(b, 14, 1)
	}
	if p.HopStart != 0 {
		b = appendVarintField(b, 15, uint64(p.HopStart))
	}
	return b
}

// UnmarshalMeshPacket decodes a protobuf-encoded MeshPacket message.
func UnmarshalMeshPacket(buf []byte) (*MeshPacket, error) {
	p := &MeshPacket{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 1:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			p.From = v
			i += m
		case 2:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			p.To = v
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.Channel = uint32(v)
			i += m
		case 4:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			d, err := UnmarshalData(v)
			if err != nil {
				return nil, err
			}
			p.Decoded = d
			p.Encrypted = nil
			i += m
		case 5:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			p.Encrypted = append([]byte(nil), v...)
			p.Decoded = nil
			i += m
		case 6:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			p.ID = v
			i += m
		case 7:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			p.RxTime = v
			i += m
		case 8:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			p.RxSNR = math.Float32frombits(v)
			i += m
		case 9:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.HopLimit = uint32(v)
			i += m
		case 10:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.WantAck = v != 0
			i += m
		case 12:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.RxRSSI = int32(v)
			i += m
		case 14:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.ViaMQTT = v != 0
			i += m
		case 15:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.HopStart = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return p, nil
}

// Marshal encodes ServiceEnvelope into protobuf wire format.
func (e *ServiceEnvelope) Marshal() []byte {
	var b []byte
	if e.Packet != nil {
		b = appendBytesField(b, 1, e.Packet.Marshal())
	}
	if e.ChannelID != "" {
		b = appendBytesField(b, 2, []byte(e.ChannelID))
	}
	if e.GatewayID != "" {
		b = appendBytesField(b, 3, []byte(e.GatewayID))
	}
	return b
}

// UnmarshalServiceEnvelope decodes a protobuf-encoded ServiceEnvelope message.
func UnmarshalServiceEnvelope(buf []byte) (*ServiceEnvelope, error) {
	e := &ServiceEnvelope{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			pkt, err := UnmarshalMeshPacket(v)
			if err != nil {
				return nil, err
			}
			e.Packet = pkt
			i += m
		case 2:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			e.ChannelID = string(v)
			i += m
		case 3:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			e.GatewayID = string(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return e, nil
}

// Marshal encodes ChannelSettings into protobuf wire format.
func (s *ChannelSettings) Marshal() []byte {
	var b []byte
	if len(s.PSK) > 0 {
		b = appendBytesField(b, 2, s.PSK)
	}
	if s.Name != "" {
		b = appendBytesField(b, 3, []byte(s.Name))
	}
	if s.ID != 0 {
		b = appendFixed32Field(b, 4, s.ID)
	}
	if s.UplinkEnabled {
		b = appendVarintField(b, 5, 1)
	}
	if s.DownlinkEnabled {
		b = appendVarintField(b, 6, 1)
	}
	return b
}

// UnmarshalChannelSettings decodes a protobuf-encoded ChannelSettings message.
func UnmarshalChannelSettings(buf []byte) (ChannelSettings, error) {
	var s ChannelSettings
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return s, err
		}
		i += n
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return s, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return s, err
			}
			s.PSK = append([]byte(nil), v...)
			i += m
		case 3:
			if wireType != 2 {
				return s, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return s, err
			}
			s.Name = string(v)
			i += m
		case 4:
			if wireType != 5 {
				return s, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return s, err
			}
			s.ID = v
			i += m
		case 5:
			if wireType != 0 {
				return s, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return s, err
			}
			s.UplinkEnabled = v != 0
			i += m
		case 6:
			if wireType != 0 {
				return s, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return s, err
			}
			s.DownlinkEnabled = v != 0
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return s, err
			}
			i += m
		}
	}
	return s, nil
}

// Marshal encodes ChannelSet into protobuf wire format.
func (cs *ChannelSet) Marshal() []byte {
	var b []byte
	for i := range cs.Settings {
		b = appendBytesField(b, 1, cs.Settings[i].Marshal())
	}
	return b
}

// UnmarshalChannelSet decodes a protobuf-encoded ChannelSet message.
func UnmarshalChannelSet(buf []byte) (*ChannelSet, error) {
	cs := &ChannelSet{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			s, err := UnmarshalChannelSettings(v)
			if err != nil {
				return nil, err
			}
			cs.Settings = append(cs.Settings, s)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return cs, nil
}

func appendVarintField(b []byte, fieldNum uint32, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(fieldNum<<3)|0)
	return binary.AppendUvarint(b, v)
}

func appendBytesField(b []byte, fieldNum uint32, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(fieldNum<<3)|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendFixed32Field(b []byte, fieldNum uint32, v uint32) []byte {
	b = binary.AppendUvarint(b, uint64(fieldNum<<3)|5)
	return binary.LittleEndian.AppendUint32(b, v)
}

func consumeTag(buf []byte) (fieldNum uint32, wireType uint8, n int, err error) {
	v, m, err := consumeVarint(buf)
	if err != nil {
		return 0, 0, 0, err
	}
	if v>>3 == 0 {
		return 0, 0, 0, fmt.Errorf("meshtastic proto: zero field number")
	}
	return uint32(v >> 3), uint8(v & 0x07), m, nil
}

func consumeVarint(buf []byte) (uint64, int, error) {
	v, n := binary.Uvarint(buf)
	if n == 0 {
		return 0, 0, errTruncatedProto
	}
	if n < 0 {
		return 0, 0, errInvalidVarint
	}
	return v, n, nil
}

func consumeFixed32(buf []byte) (uint32, int, error) {
	if len(buf) < 4 {
		return 0, 0, errTruncatedProto
	}
	return binary.LittleEndian.Uint32(buf[:4]), 4, nil
}

func consumeBytes(buf []byte) ([]byte, int, error) {
	l, n, err := consumeVarint(buf)
	if err != nil {
		return nil, 0, err
	}
	if l > uint64(len(buf)-n) {
		return nil, 0, errTruncatedProto
	}
	end := n + int(l)
	return buf[n:end], end, nil
}

func skipField(buf []byte, wireType uint8) (int, error) {
	switch wireType {
	case 0:
		_, n, err := consumeVarint(buf)
		return n, err
	case 1:
		if len(buf) < 8 {
			return 0, errTruncatedProto
		}
		return 8, nil
	case 2:
		_, n, err := consumeBytes(buf)
		return n, err
	case 5:
		if len(buf) < 4 {
			return 0, errTruncatedProto
		}
		return 4, nil
	default:
		return 0, errInvalidWire
	}
}
