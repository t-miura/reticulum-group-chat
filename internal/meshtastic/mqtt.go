package meshtastic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

const (
	mqttKeepAliveSecs = 60
	mqttDialTimeout   = 15 * time.Second
	mqttMaxPacketSize = 1024 * 1024
)

// DefaultMQTTRootTopic is the Meshtastic community root topic prefix.
const DefaultMQTTRootTopic = "msh/US"

// MQTTTransport connects to an MQTT v3.1.1 broker and exchanges
// ServiceEnvelope protobuf payloads on <root_topic>/2/e/<channel_name>/+.
type MQTTTransport struct {
	broker      string
	username    string
	password    string
	rootTopic   string
	channelName string
	bridgeHex   string // 8-char lowercase hex (without '!')
	logger      *logging.Logger

	// dialFn, when set (tests), overrides dialMQTTBroker.
	dialFn func(ctx context.Context, broker string) (net.Conn, error)

	mu        sync.Mutex
	conn      net.Conn
	connected bool
	writeMu   sync.Mutex
	subReady  chan struct{}
}

// NewMQTTTransport constructs an MQTTTransport for the configured broker and channel.
func NewMQTTTransport(broker, username, password, rootTopic, channelName, bridgeHex string, logger *logging.Logger) *MQTTTransport {
	if strings.TrimSpace(rootTopic) == "" {
		rootTopic = DefaultMQTTRootTopic
	}
	rootTopic = strings.TrimRight(strings.TrimSpace(rootTopic), "/")
	return &MQTTTransport{
		broker:      strings.TrimSpace(broker),
		username:    username,
		password:    password,
		rootTopic:   rootTopic,
		channelName: channelName,
		bridgeHex:   strings.ToLower(strings.TrimPrefix(bridgeHex, "!")),
		logger:      logger,
		subReady:    make(chan struct{}),
	}
}

func (m *MQTTTransport) Name() string { return "mqtt" }

// SubTopic returns the subscribed MQTT topic filter.
func (m *MQTTTransport) SubTopic() string {
	return m.rootTopic + "/2/e/" + m.channelName + "/+"
}

// PubTopic returns the MQTT topic this bridge publishes ServiceEnvelopes to.
func (m *MQTTTransport) PubTopic() string {
	return m.rootTopic + "/2/e/" + m.channelName + "/!" + m.bridgeHex
}

// Connected reports whether an active MQTT session is currently established.
func (m *MQTTTransport) Connected() bool {
	m.mu.Lock()
	c := m.connected
	m.mu.Unlock()
	return c
}

// Ready returns a channel closed after the first successful SUBSCRIBE.
func (m *MQTTTransport) Ready() <-chan struct{} {
	return m.subReady
}

// Run maintains a reconnecting MQTT v3.1.1 session until ctx is cancelled.
func (m *MQTTTransport) Run(ctx context.Context, onPacket func(*MeshPacket)) error {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		subOK, err := m.runSession(ctx, onPacket)
		if ctx.Err() != nil {
			return nil
		}
		if subOK {
			backoff = 2 * time.Second
		}
		if err != nil && m.logger != nil {
			m.logger.Warnf("meshtastic mqtt disconnected (%v); reconnecting in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (m *MQTTTransport) runSession(ctx context.Context, onPacket func(*MeshPacket)) (bool, error) {
	dial := dialMQTTBroker
	if m.dialFn != nil {
		dial = m.dialFn
	}
	conn, err := dial(ctx, m.broker)
	if err != nil {
		return false, err
	}

	defer func() {
		m.mu.Lock()
		m.connected = false
		if m.conn == conn {
			m.conn = nil
		}
		m.mu.Unlock()
		_ = conn.Close()
	}()

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	go func() {
		<-sessionCtx.Done()
		// Best-effort DISCONNECT before closing socket.
		m.writeMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte{0xE0, 0x00})
		m.writeMu.Unlock()
		_ = conn.Close()
	}()

	br := bufio.NewReader(conn)

	// 1. CONNECT
	clientID := "fwdsvc-" + m.bridgeHex
	connectPkt := encodeMQTTConnect(clientID, m.username, m.password, mqttKeepAliveSecs)
	if err := m.writeRaw(conn, connectPkt); err != nil {
		return false, fmt.Errorf("send CONNECT: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(mqttDialTimeout))
	ptype, _, payload, err := readMQTTPacket(br)
	if err != nil {
		return false, fmt.Errorf("read CONNACK: %w", err)
	}
	if ptype != 2 || len(payload) < 2 {
		return false, fmt.Errorf("unexpected CONNACK packet type=%d len=%d", ptype, len(payload))
	}
	if payload[1] != 0 {
		return false, fmt.Errorf("MQTT broker refused connection (code %d)", payload[1])
	}

	// 2. SUBSCRIBE
	subTopic := m.SubTopic()
	subPkt := encodeMQTTSubscribe(1, subTopic)
	if err := m.writeRaw(conn, subPkt); err != nil {
		return false, fmt.Errorf("send SUBSCRIBE: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(mqttDialTimeout))
	ptype, _, payload, err = readMQTTPacket(br)
	if err != nil {
		return false, fmt.Errorf("read SUBACK: %w", err)
	}
	if ptype != 9 || len(payload) < 3 {
		return false, fmt.Errorf("unexpected SUBACK packet type=%d len=%d", ptype, len(payload))
	}
	if payload[2] == 0x80 {
		return false, fmt.Errorf("MQTT broker rejected subscription to %q", subTopic)
	}

	m.mu.Lock()
	m.conn = conn
	m.connected = true
	select {
	case <-m.subReady:
	default:
		close(m.subReady)
	}
	m.mu.Unlock()

	if m.logger != nil {
		m.logger.Infof("meshtastic mqtt connected to %s (sub %s)", m.broker, subTopic)
	}

	// Keepalive pinger.
	go func() {
		ticker := time.NewTicker(time.Duration(mqttKeepAliveSecs/2) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				if err := m.writeRaw(conn, []byte{0xC0, 0x00}); err != nil {
					cancelSession()
					return
				}
			}
		}
	}()

	// 3. Read loop
	readTimeout := time.Duration(mqttKeepAliveSecs*2) * time.Second
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		ptype, flags, body, err := readMQTTPacket(br)
		if err != nil {
			if sessionCtx.Err() != nil {
				return true, nil
			}
			return true, err
		}
		switch ptype {
		case 3: // PUBLISH
			qos := (flags >> 1) & 0x03
			_, pid, msgPayload, perr := decodeMQTTPublish(body, qos)
			if perr != nil {
				if m.logger != nil {
					m.logger.Debugf("meshtastic mqtt malformed PUBLISH: %v", perr)
				}
				continue
			}
			if qos == 1 && pid != 0 {
				_ = m.writeRaw(conn, []byte{0x40, 0x02, byte(pid >> 8), byte(pid)})
			}
			env, uerr := UnmarshalServiceEnvelope(msgPayload)
			if uerr != nil || env.Packet == nil {
				continue
			}
			if env.ChannelID != "" && env.ChannelID != m.channelName {
				continue
			}
			if env.GatewayID != "" && strings.EqualFold(strings.TrimPrefix(env.GatewayID, "!"), m.bridgeHex) {
				continue
			}
			if onPacket != nil {
				onPacket(env.Packet)
			}
		case 13: // PINGRESP
		default:
		}
	}
}

// Send wraps pkt in a ServiceEnvelope and publishes it with QoS 0 to PubTopic().
func (m *MQTTTransport) Send(_ context.Context, pkt *MeshPacket) error {
	if pkt == nil {
		return nil
	}
	m.mu.Lock()
	conn := m.conn
	connected := m.connected
	m.mu.Unlock()

	if !connected || conn == nil {
		return fmt.Errorf("meshtastic mqtt not connected")
	}

	env := &ServiceEnvelope{
		Packet:    pkt,
		ChannelID: m.channelName,
		GatewayID: "!" + m.bridgeHex,
	}
	pub := encodeMQTTPublish(m.PubTopic(), env.Marshal())
	if err := m.writeRaw(conn, pub); err != nil {
		m.mu.Lock()
		if m.conn == conn {
			m.connected = false
		}
		m.mu.Unlock()
		_ = conn.Close()
		return fmt.Errorf("meshtastic mqtt publish: %w", err)
	}
	if m.logger != nil {
		m.logger.Debugf("meshtastic mqtt published id=0x%08x to %s (%d B)", pkt.ID, m.PubTopic(), len(pub))
	}
	return nil
}

func (m *MQTTTransport) writeRaw(conn net.Conn, data []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.Write(data)
	return err
}

func dialMQTTBroker(ctx context.Context, broker string) (net.Conn, error) {
	if !strings.Contains(broker, "://") {
		broker = "tcp://" + broker
	}
	u, err := url.Parse(broker)
	if err != nil {
		return nil, fmt.Errorf("parse mqtt broker %q: %w", broker, err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("mqtt broker %q missing host", broker)
	}
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		switch scheme {
		case "tls", "ssl", "mqtts":
			host = net.JoinHostPort(host, "8883")
		default:
			host = net.JoinHostPort(host, "1883")
		}
	}
	dialer := &net.Dialer{Timeout: mqttDialTimeout}
	switch scheme {
	case "tcp", "mqtt", "":
		return dialer.DialContext(ctx, "tcp", host)
	case "tls", "ssl", "mqtts":
		serverName, _, _ := net.SplitHostPort(host)
		return tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})
	default:
		return nil, fmt.Errorf("unsupported mqtt broker scheme %q", scheme)
	}
}

func encodeMQTTConnect(clientID, username, password string, keepAliveSecs uint16) []byte {
	var vh []byte
	vh = appendMQTTString(vh, "MQTT")
	vh = append(vh, 0x04) // MQTT 3.1.1
	flags := byte(0x02)   // Clean Session
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	vh = append(vh, flags)
	vh = binary.BigEndian.AppendUint16(vh, keepAliveSecs)

	var payload []byte
	payload = appendMQTTString(payload, clientID)
	if username != "" {
		payload = appendMQTTString(payload, username)
	}
	if password != "" {
		payload = appendMQTTString(payload, password)
	}
	return frameMQTTPacket(1, 0, append(vh, payload...))
}

func encodeMQTTSubscribe(packetID uint16, topic string) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, packetID)
	body = appendMQTTString(body, topic)
	body = append(body, 0x00) // max QoS 0
	return frameMQTTPacket(8, 0x02, body)
}

func encodeMQTTPublish(topic string, payload []byte) []byte {
	var body []byte
	body = appendMQTTString(body, topic)
	body = append(body, payload...)
	return frameMQTTPacket(3, 0x00, body)
}

func decodeMQTTPublish(body []byte, qos byte) (topic string, packetID uint16, payload []byte, err error) {
	if len(body) < 2 {
		return "", 0, nil, errors.New("truncated PUBLISH topic")
	}
	tlen := int(binary.BigEndian.Uint16(body[:2]))
	idx := 2
	if len(body) < idx+tlen {
		return "", 0, nil, errors.New("truncated PUBLISH topic bytes")
	}
	topic = string(body[idx : idx+tlen])
	idx += tlen
	if qos > 0 {
		if len(body) < idx+2 {
			return "", 0, nil, errors.New("truncated PUBLISH packet id")
		}
		packetID = binary.BigEndian.Uint16(body[idx : idx+2])
		idx += 2
	}
	return topic, packetID, body[idx:], nil
}

func appendMQTTString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func frameMQTTPacket(ptype, flags byte, body []byte) []byte {
	header := byte((ptype << 4) | (flags & 0x0F))
	var out []byte
	out = append(out, header)
	rem := len(body)
	for {
		encodedByte := byte(rem % 128)
		rem /= 128
		if rem > 0 {
			encodedByte |= 0x80
		}
		out = append(out, encodedByte)
		if rem == 0 {
			break
		}
	}
	return append(out, body...)
}

func readMQTTPacket(r *bufio.Reader) (ptype, flags byte, body []byte, err error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	ptype = first >> 4
	flags = first & 0x0F

	multiplier := 1
	remLen := 0
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		remLen += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			break
		}
		if i == 3 {
			return 0, 0, nil, errors.New("mqtt remaining length overflow")
		}
		multiplier *= 128
	}
	if remLen > mqttMaxPacketSize {
		return 0, 0, nil, fmt.Errorf("mqtt packet too large (%d > %d)", remLen, mqttMaxPacketSize)
	}
	body = make([]byte, remLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return ptype, flags, body, nil
}
