// Package meshtastic implements a wire-compatible Meshtastic channel bridge
// (protobuf codec, PSK AES-CTR encryption, UDP multicast, MQTT v3.1.1,
// TCP StreamAPI client, node DB, and chunking) using only the Go standard library.
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
	PortNumRoutingApp     uint32 = 5
)

// ChannelRole identifies meshtastic.Channel.Role (channel.proto).
const (
	ChannelRoleDisabled  uint32 = 0
	ChannelRolePrimary   uint32 = 1
	ChannelRoleSecondary uint32 = 2
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
	Priority  uint32
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
	UseAEAD         bool
}

// Channel corresponds to meshtastic.Channel (channel.proto).
type Channel struct {
	Index       int32
	Settings    ChannelSettings
	HasSettings bool
	Role        uint32
}

// ChannelSet corresponds to meshtastic.ChannelSet (apponly.proto).
type ChannelSet struct {
	Settings []ChannelSettings
}

// MyNodeInfo corresponds to meshtastic.MyNodeInfo (mesh.proto).
type MyNodeInfo struct {
	MyNodeNum   uint32
	RebootCount uint32
	NodeDBCount uint32
}

// NodeInfo corresponds to meshtastic.NodeInfo (mesh.proto).
type NodeInfo struct {
	Num       uint32
	User      *User
	LastHeard uint32
	Channel   uint32
	ViaMQTT   bool
}

// LoRaConfig corresponds to meshtastic.Config.LoRaConfig (config.proto).
type LoRaConfig struct {
	UsePreset   bool
	ModemPreset uint32
	Region      uint32
	HopLimit    uint32
}

// RadioConfig corresponds to meshtastic.Config (config.proto).
type RadioConfig struct {
	LoRa *LoRaConfig
}

// QueueStatus corresponds to meshtastic.QueueStatus (mesh.proto).
type QueueStatus struct {
	Res          int32
	Free         uint32
	Maxlen       uint32
	MeshPacketID uint32
}

// ClientNotification corresponds to meshtastic.ClientNotification (mesh.proto).
type ClientNotification struct {
	ReplyID uint32
	Time    uint32
	Level   uint32
	Message string
	Type    uint32
}

// Heartbeat corresponds to meshtastic.Heartbeat (mesh.proto).
type Heartbeat struct {
	Nonce uint32
}

// ToRadio corresponds to meshtastic.ToRadio (mesh.proto).
type ToRadio struct {
	Packet       *MeshPacket
	WantConfigID uint32
	Disconnect   bool
	Heartbeat    *Heartbeat
}

// FromRadio corresponds to meshtastic.FromRadio (mesh.proto).
type FromRadio struct {
	ID                  uint32
	Packet              *MeshPacket
	MyInfo              *MyNodeInfo
	NodeInfo            *NodeInfo
	Config              *RadioConfig
	ConfigCompleteID    uint32
	HasConfigCompleteID bool
	Rebooted            bool
	Channel             *Channel
	QueueStatus         *QueueStatus
	ClientNotification  *ClientNotification
}

// Routing corresponds to meshtastic.Routing (mesh.proto).
type Routing struct {
	ErrorReason uint32
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
	if p.Priority != 0 {
		b = appendVarintField(b, 11, uint64(p.Priority))
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
		case 11:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			p.Priority = uint32(v)
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
	if s.UseAEAD {
		b = appendVarintField(b, 8, 1)
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
		case 8:
			if wireType != 0 {
				return s, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return s, err
			}
			s.UseAEAD = v != 0
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

// Marshal encodes Channel into protobuf wire format.
func (c *Channel) Marshal() []byte {
	var b []byte
	if c.Index != 0 {
		b = appendVarintField(b, 1, uint64(int64(c.Index)))
	}
	if c.HasSettings {
		b = appendBytesField(b, 2, c.Settings.Marshal())
	} else {
		raw := c.Settings.Marshal()
		if len(raw) > 0 {
			b = appendBytesField(b, 2, raw)
		}
	}
	if c.Role != 0 {
		b = appendVarintField(b, 3, uint64(c.Role))
	}
	return b
}

// UnmarshalChannel decodes a protobuf-encoded Channel message.
func UnmarshalChannel(buf []byte) (*Channel, error) {
	c := &Channel{}
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
			c.Index = int32(v)
			i += m
		case 2:
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
			c.Settings = s
			c.HasSettings = true
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			c.Role = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return c, nil
}

// Marshal encodes MyNodeInfo into protobuf wire format.
func (m *MyNodeInfo) Marshal() []byte {
	var b []byte
	if m.MyNodeNum != 0 {
		b = appendVarintField(b, 1, uint64(m.MyNodeNum))
	}
	if m.RebootCount != 0 {
		b = appendVarintField(b, 8, uint64(m.RebootCount))
	}
	if m.NodeDBCount != 0 {
		b = appendVarintField(b, 15, uint64(m.NodeDBCount))
	}
	return b
}

// UnmarshalMyNodeInfo decodes a protobuf-encoded MyNodeInfo message.
func UnmarshalMyNodeInfo(buf []byte) (*MyNodeInfo, error) {
	mi := &MyNodeInfo{}
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
			mi.MyNodeNum = uint32(v)
			i += m
		case 8:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			mi.RebootCount = uint32(v)
			i += m
		case 15:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			mi.NodeDBCount = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return mi, nil
}

// Marshal encodes NodeInfo into protobuf wire format.
func (ni *NodeInfo) Marshal() []byte {
	var b []byte
	if ni.Num != 0 {
		b = appendVarintField(b, 1, uint64(ni.Num))
	}
	if ni.User != nil {
		b = appendBytesField(b, 2, ni.User.Marshal())
	}
	if ni.LastHeard != 0 {
		b = appendFixed32Field(b, 5, ni.LastHeard)
	}
	if ni.Channel != 0 {
		b = appendVarintField(b, 7, uint64(ni.Channel))
	}
	if ni.ViaMQTT {
		b = appendVarintField(b, 8, 1)
	}
	return b
}

// UnmarshalNodeInfo decodes a protobuf-encoded NodeInfo message.
func UnmarshalNodeInfo(buf []byte) (*NodeInfo, error) {
	ni := &NodeInfo{}
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
			ni.Num = uint32(v)
			i += m
		case 2:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			u, err := UnmarshalUser(v)
			if err != nil {
				return nil, err
			}
			ni.User = u
			i += m
		case 5:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			ni.LastHeard = v
			i += m
		case 7:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			ni.Channel = uint32(v)
			i += m
		case 8:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			ni.ViaMQTT = v != 0
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return ni, nil
}

// Marshal encodes LoRaConfig into protobuf wire format.
func (l *LoRaConfig) Marshal() []byte {
	var b []byte
	if l.UsePreset {
		b = appendVarintField(b, 1, 1)
	}
	if l.ModemPreset != 0 {
		b = appendVarintField(b, 2, uint64(l.ModemPreset))
	}
	if l.Region != 0 {
		b = appendVarintField(b, 7, uint64(l.Region))
	}
	if l.HopLimit != 0 {
		b = appendVarintField(b, 8, uint64(l.HopLimit))
	}
	return b
}

// UnmarshalLoRaConfig decodes a protobuf-encoded Config.LoRaConfig message.
func UnmarshalLoRaConfig(buf []byte) (*LoRaConfig, error) {
	l := &LoRaConfig{}
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
			l.UsePreset = v != 0
			i += m
		case 2:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			l.ModemPreset = uint32(v)
			i += m
		case 7:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			l.Region = uint32(v)
			i += m
		case 8:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			l.HopLimit = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return l, nil
}

// Marshal encodes RadioConfig (meshtastic.Config) into protobuf wire format.
func (rc *RadioConfig) Marshal() []byte {
	var b []byte
	if rc.LoRa != nil {
		b = appendBytesField(b, 6, rc.LoRa.Marshal())
	}
	return b
}

// UnmarshalRadioConfig decodes a protobuf-encoded meshtastic.Config message.
func UnmarshalRadioConfig(buf []byte) (*RadioConfig, error) {
	rc := &RadioConfig{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 6:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			l, err := UnmarshalLoRaConfig(v)
			if err != nil {
				return nil, err
			}
			rc.LoRa = l
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return rc, nil
}

// Marshal encodes QueueStatus into protobuf wire format.
func (q *QueueStatus) Marshal() []byte {
	var b []byte
	if q.Res != 0 {
		b = appendVarintField(b, 1, uint64(int64(q.Res)))
	}
	if q.Free != 0 {
		b = appendVarintField(b, 2, uint64(q.Free))
	}
	if q.Maxlen != 0 {
		b = appendVarintField(b, 3, uint64(q.Maxlen))
	}
	if q.MeshPacketID != 0 {
		b = appendVarintField(b, 4, uint64(q.MeshPacketID))
	}
	return b
}

// UnmarshalQueueStatus decodes a protobuf-encoded QueueStatus message.
func UnmarshalQueueStatus(buf []byte) (*QueueStatus, error) {
	q := &QueueStatus{}
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
			q.Res = int32(v)
			i += m
		case 2:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			q.Free = uint32(v)
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			q.Maxlen = uint32(v)
			i += m
		case 4:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			q.MeshPacketID = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return q, nil
}

// Marshal encodes ClientNotification into protobuf wire format.
func (cn *ClientNotification) Marshal() []byte {
	var b []byte
	if cn.ReplyID != 0 {
		b = appendVarintField(b, 1, uint64(cn.ReplyID))
	}
	if cn.Time != 0 {
		b = appendFixed32Field(b, 2, cn.Time)
	}
	if cn.Level != 0 {
		b = appendVarintField(b, 3, uint64(cn.Level))
	}
	if cn.Message != "" {
		b = appendBytesField(b, 4, []byte(cn.Message))
	}
	if cn.Type != 0 {
		b = appendVarintField(b, 5, uint64(cn.Type))
	}
	return b
}

// UnmarshalClientNotification decodes a protobuf-encoded ClientNotification message.
func UnmarshalClientNotification(buf []byte) (*ClientNotification, error) {
	cn := &ClientNotification{}
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
			cn.ReplyID = uint32(v)
			i += m
		case 2:
			if wireType != 5 {
				return nil, errInvalidWire
			}
			v, m, err := consumeFixed32(buf[i:])
			if err != nil {
				return nil, err
			}
			cn.Time = v
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			cn.Level = uint32(v)
			i += m
		case 4:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			cn.Message = string(v)
			i += m
		case 5:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			cn.Type = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return cn, nil
}

// Marshal encodes Heartbeat into protobuf wire format.
func (h *Heartbeat) Marshal() []byte {
	var b []byte
	if h.Nonce != 0 {
		b = appendVarintField(b, 1, uint64(h.Nonce))
	}
	return b
}

// UnmarshalHeartbeat decodes a protobuf-encoded Heartbeat message.
func UnmarshalHeartbeat(buf []byte) (*Heartbeat, error) {
	h := &Heartbeat{}
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
			h.Nonce = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return h, nil
}

// Marshal encodes ToRadio into protobuf wire format.
func (tr *ToRadio) Marshal() []byte {
	var b []byte
	switch {
	case tr.Packet != nil:
		b = appendBytesField(b, 1, tr.Packet.Marshal())
	case tr.WantConfigID != 0:
		b = appendVarintField(b, 3, uint64(tr.WantConfigID))
	case tr.Disconnect:
		b = appendVarintField(b, 4, 1)
	case tr.Heartbeat != nil:
		// Always emit the empty length-delimited submessage (0x3A 0x00) when
		// Nonce == 0 so PhoneAPI selects which_payload_variant = heartbeat_tag.
		b = appendBytesField(b, 7, tr.Heartbeat.Marshal())
	}
	return b
}

// UnmarshalToRadio decodes a protobuf-encoded ToRadio message.
func UnmarshalToRadio(buf []byte) (*ToRadio, error) {
	tr := &ToRadio{}
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
			tr.Packet = pkt
			i += m
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			tr.WantConfigID = uint32(v)
			i += m
		case 4:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			tr.Disconnect = v != 0
			i += m
		case 7:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			hb, err := UnmarshalHeartbeat(v)
			if err != nil {
				return nil, err
			}
			tr.Heartbeat = hb
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return tr, nil
}

// Marshal encodes FromRadio into protobuf wire format.
func (fr *FromRadio) Marshal() []byte {
	var b []byte
	if fr.ID != 0 {
		b = appendVarintField(b, 1, uint64(fr.ID))
	}
	switch {
	case fr.Packet != nil:
		b = appendBytesField(b, 2, fr.Packet.Marshal())
	case fr.MyInfo != nil:
		b = appendBytesField(b, 3, fr.MyInfo.Marshal())
	case fr.NodeInfo != nil:
		b = appendBytesField(b, 4, fr.NodeInfo.Marshal())
	case fr.Config != nil:
		b = appendBytesField(b, 5, fr.Config.Marshal())
	case fr.HasConfigCompleteID || fr.ConfigCompleteID != 0:
		b = appendVarintField(b, 7, uint64(fr.ConfigCompleteID))
	case fr.Rebooted:
		b = appendVarintField(b, 8, 1)
	case fr.Channel != nil:
		b = appendBytesField(b, 10, fr.Channel.Marshal())
	case fr.QueueStatus != nil:
		b = appendBytesField(b, 11, fr.QueueStatus.Marshal())
	case fr.ClientNotification != nil:
		b = appendBytesField(b, 16, fr.ClientNotification.Marshal())
	}
	return b
}

// UnmarshalFromRadio decodes a protobuf-encoded FromRadio message.
func UnmarshalFromRadio(buf []byte) (*FromRadio, error) {
	fr := &FromRadio{}
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
			fr.ID = uint32(v)
			i += m
		case 2:
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
			fr.Packet = pkt
			i += m
		case 3:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			mi, err := UnmarshalMyNodeInfo(v)
			if err != nil {
				return nil, err
			}
			fr.MyInfo = mi
			i += m
		case 4:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			ni, err := UnmarshalNodeInfo(v)
			if err != nil {
				return nil, err
			}
			fr.NodeInfo = ni
			i += m
		case 5:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			rc, err := UnmarshalRadioConfig(v)
			if err != nil {
				return nil, err
			}
			fr.Config = rc
			i += m
		case 7:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			fr.ConfigCompleteID = uint32(v)
			fr.HasConfigCompleteID = true
			i += m
		case 8:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			fr.Rebooted = v != 0
			i += m
		case 10:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			ch, err := UnmarshalChannel(v)
			if err != nil {
				return nil, err
			}
			fr.Channel = ch
			i += m
		case 11:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			qs, err := UnmarshalQueueStatus(v)
			if err != nil {
				return nil, err
			}
			fr.QueueStatus = qs
			i += m
		case 16:
			if wireType != 2 {
				return nil, errInvalidWire
			}
			v, m, err := consumeBytes(buf[i:])
			if err != nil {
				return nil, err
			}
			cn, err := UnmarshalClientNotification(v)
			if err != nil {
				return nil, err
			}
			fr.ClientNotification = cn
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return fr, nil
}

// UnmarshalRouting decodes a protobuf-encoded meshtastic.Routing message.
func UnmarshalRouting(buf []byte) (*Routing, error) {
	r := &Routing{}
	i := 0
	for i < len(buf) {
		fieldNum, wireType, n, err := consumeTag(buf[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch fieldNum {
		case 3:
			if wireType != 0 {
				return nil, errInvalidWire
			}
			v, m, err := consumeVarint(buf[i:])
			if err != nil {
				return nil, err
			}
			r.ErrorReason = uint32(v)
			i += m
		default:
			m, err := skipField(buf[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return r, nil
}

// ModemPresetDisplayName returns the Meshtastic canonical channel display name
// for an unnamed channel under the given LoRaConfig modem preset (matching
// DisplayFormatters::getModemPresetDisplayName in meshtastic/firmware).
func ModemPresetDisplayName(preset uint32, usePreset bool) string {
	if !usePreset {
		return "Custom"
	}
	switch preset {
	case 0:
		return "LongFast"
	case 1:
		return "LongSlow"
	case 2:
		return "VeryLongSlow"
	case 3:
		return "MediumSlow"
	case 4:
		return "MediumFast"
	case 5:
		return "ShortSlow"
	case 6:
		return "ShortFast"
	case 7:
		return "LongMod"
	case 8:
		return "ShortTurbo"
	case 9:
		return "LongTurbo"
	case 10:
		return "LiteFast"
	case 11:
		return "LiteSlow"
	case 12:
		return "NarrowFast"
	case 13:
		return "NarrowSlow"
	case 14:
		return "TinyFast"
	case 15:
		return "TinySlow"
	case 16:
		return "MediumTurbo"
	default:
		return "LongFast"
	}
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
