package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/meshtastic"
)

const identityHashLen = 16

// identityPrivateKeyLen is the on-disk Reticulum identity blob: 32-byte
// X25519 private key concatenated with 32-byte Ed25519 seed (SPEC §1.3).
// Duplicated here from rns.PrivateKeyLen to keep config validation
// independent of the rns package import.
const identityPrivateKeyLen = 64

type Config struct {
	Service     ServiceConfig     `toml:"service"`
	Interfaces  []InterfaceConfig `toml:"interfaces"`
	Replay      ReplayConfig      `toml:"replay"`
	Propagation PropagationConfig `toml:"propagation"`
	Meshtastic  MeshtasticConfig  `toml:"meshtastic"`
	Admins      []string          `toml:"admins"`
	Mods        []string          `toml:"mods"`

	// Warnings holds non-fatal problems found while loading — currently
	// keys the file sets that no field consumes. Load cannot log (it runs
	// before the logger is configured and is shared with tests), so the
	// caller prints these at startup.
	//
	// This exists because an unrecognised key used to be dropped without
	// a word. An operator put inbound_stamp_cost and
	// enforce_inbound_stamps at the top of the file beside admins/mods —
	// the header comment says those two must go there — and TOML scoped
	// them to the root table, where nothing reads them. The relay started
	// cleanly with stamps fully off while the operator believed
	// enforcement was on; even normalize's "enforce requires cost > 0"
	// check never fired, because neither value arrived.
	//
	// A warning rather than an error so that an upgrade cannot refuse to
	// start a deployment that has been carrying a harmless stray key.
	Warnings []string `toml:"-"`
}

// PropagationConfig controls store-and-forward delivery via LXMF
// propagation nodes (SPEC §5.8). When enabled, messages the service
// can't deliver directly (recipient offline / unreachable) are handed
// to a propagation node, where the recipient's own client (Sideband
// etc.) fetches them on its next sync — instead of being dropped after
// the direct-retry budget is exhausted.
type PropagationConfig struct {
	// Enabled turns propagation-node submission on. Default false —
	// existing deployments keep the direct-only behavior.
	Enabled bool `toml:"enabled"`

	// Node optionally pins one propagation node by destination hash
	// (32 hex chars, the lxmf.propagation destination). When empty, the
	// service auto-selects the most recently heard node that announces
	// itself as accepting messages.
	Node string `toml:"node"`

	// Mode selects when propagation is used:
	//   "fallback" (default) — try direct delivery first; when the
	//     direct retry budget is exhausted, re-route the message via the
	//     propagation node instead of dropping it.
	//   "always" — every outbound message goes to the propagation node
	//     only; recipients get everything on their next sync.
	Mode string `toml:"mode"`

	// DirectAttempts SHORTENS the direct-delivery retry budget — but
	// only while a propagation node is actually available to fall back
	// to. The standard budget is 5 attempts (upstream LXMF's
	// MAX_DELIVERY_ATTEMPTS), sized for the case where exhausting it
	// DROPS the message; with a fallback route, extra direct attempts
	// mostly delay the re-route, so failing over sooner gets an offline
	// member's mail onto the node in ~75s instead of ~3.5min. Whenever
	// no node is known (none discovered, none accepting), the full
	// 5-attempt budget still applies before a message is given up on.
	// Only meaningful in mode "fallback". Default 3. Values >= 5
	// disable the shortening (the standard budget wins).
	DirectAttempts int `toml:"direct_attempts"`
}

// Propagation mode values accepted in PropagationConfig.Mode.
const (
	PropagationModeFallback = "fallback"
	PropagationModeAlways   = "always"
)

// Reserved LXMF field keys the relay stamps itself (see
// internal/service/rewrite.go). They must never be forwarded from
// inbound messages.
const (
	fieldOriginatorIdentity = 251 // 0xFB
	fieldOriginatorHash     = 252 // 0xFC
)

// DefaultMaxMembers bounds the roster by default. Chosen to be far
// above any realistic group-chat membership while still denying an
// attacker unbounded growth of state, fan-out cost, and reply size.
const DefaultMaxMembers = 512

// MaxAnnouncedStampCost is the largest §5.7.2 stamp cost that can be
// announced in app_data element [1]. Upstream LXMF accepts 1..254, and
// rns.DecodeLXMFAppDataStampCost mirrors that range — announcing
// anything outside it makes our announce unparseable to the peers we
// are asking to do the work.
const MaxAnnouncedStampCost = 254

// DefaultPropagationDirectAttempts is the direct-delivery budget used
// while a propagation fallback node is available. Applied by normalize
// when direct_attempts is unset (0).
const DefaultPropagationDirectAttempts = 3

// NodeBytes returns the pinned propagation node's destination hash, or
// nil when no node is pinned. Only valid after Load/normalize.
func (p *PropagationConfig) NodeBytes() []byte {
	if p.Node == "" {
		return nil
	}
	raw, err := hex.DecodeString(p.Node)
	if err != nil || len(raw) != identityHashLen {
		return nil
	}
	return raw
}

type ServiceConfig struct {
	DisplayName  string `toml:"display_name"`
	IdentityPath string `toml:"identity_path"`

	// IdentityB64 is an optional base64-encoded backup of the 64-byte
	// Reticulum private key (X25519 priv 32 || Ed25519 seed 32). When
	// set, it takes precedence over IdentityPath — the on-disk file is
	// ignored and not written to. The field exists so an operator can
	// keep their identity inside the same config they back up before a
	// reinstall, instead of remembering to also copy the binary
	// identity file.
	//
	// Treat as a SECRET — anyone with this string is your service.
	// Generated automatically on first run alongside the binary
	// identity file (see <state_dir>/identity.b64.txt) and logged with
	// instructions; subsequent runs read the file and leave the config
	// untouched until the operator chooses to copy the b64 value in.
	IdentityB64 string `toml:"identity_b64"`

	StatePath        string   `toml:"state_path"`
	HistoryPath      string   `toml:"history_path"`
	LogPath          string   `toml:"log_path"`
	PruneAfter       Duration `toml:"prune_after"`

	// LogLevel is the lowest severity written: "debug", "info", "warn" or
	// "error". Empty means "info", which is everything fwdsvc logged before
	// levels existed apart from per-transfer protocol chatter.
	//
	// The default stays at info, not warn, because the lines operators
	// size policy from are info: "inbound stamp:" before enforcing stamps,
	// "new sender contact:" to find a hash for admins. A hub that wants a
	// quiet journal sets "warn" here — or, under systemd, keeps info and
	// sets LogLevelMax=warning in the unit, since each line carries a
	// journald priority either way (see internal/logging).
	LogLevel string `toml:"log_level"`

	// LogLevelValue is LogLevel parsed by normalize; it is what the
	// service reads.
	LogLevelValue rns.LogLevel `toml:"-"`

	// PruneSilentAfter removes members who have not sent a chat message in
	// this window, IGNORING announces AND commands — i.e. lurkers who joined
	// and went quiet but whose Reticulum client keeps re-announcing in the
	// background, or who only ever poke at read-only commands (so
	// PruneAfter, which counts both as activity, never catches them).
	// Normally set larger than PruneAfter (e.g. prune_after = "4w",
	// prune_silent_after = "6w"). 0 disables the silent sweep.
	PruneSilentAfter Duration `toml:"prune_silent_after"`

	PruneInterval    Duration `toml:"prune_interval"`
	AnnounceInterval Duration `toml:"announce_interval"`

	// MaxInboundChars caps how many UTF-8 characters an inbound message
	// from a roster member may contain. Anything longer is rejected with
	// a polite reply to the sender — the message is not forwarded, not
	// added to history, and the sender is not joined to the roster on
	// the back of an oversized first message. This is a spam-prevention
	// policy limit, separate from the wire-format size cap.
	// 0 = unlimited (not recommended). Default: 500.
	MaxInboundChars int `toml:"max_inbound_chars"`

	// MaxMembers caps the size of the roster. /join attempts past this
	// limit are refused with a polite "the chat is full" reply; the
	// would-be joiner is not added. Existing members and paused members
	// both count toward the limit.
	//
	// Defaults to DefaultMaxMembers rather than unlimited: in an open
	// (unlocked) group anyone can mint identities and /join, and roster
	// size multiplies every fan-out — each new member adds an outbound
	// queue entry per message, a replay burst on join, and a line in
	// every /users reply. Prune runs hourly against multi-week windows,
	// so it is no defense against a burst. Set to 0 for genuinely
	// unlimited (not recommended on an open group).
	MaxMembers int `toml:"max_members"`

	// DedupWindow is how long an inbound LXMF message_id is remembered so a
	// message delivered more than once — via multiple interfaces, a
	// retransmit, or a propagation-node replay — is forwarded to the roster
	// only once. Reticulum can and does redeliver the same message, and
	// neither the transport nor the LXMF layer dedups, so without this every
	// duplicate is fanned out again (a prime source of duplicate/echoed
	// group messages). message_id includes the sender's timestamp, so two
	// genuinely distinct sends are never collapsed. 0 disables. Default 1h.
	DedupWindow Duration `toml:"dedup_window"`

	// Locked makes the chat invite-only. When true, /join from a regular
	// (non config-admin/mod) user is refused with a "closed group" reply
	// that echoes the user their own destination hash, and the ONLY way
	// into the roster is an admin/mod running /adduser <hash>. The added
	// user is proactively welcomed and replayed exactly as if they had
	// joined themselves. Config admins/mods always bypass the gate so an
	// operator can never lock themselves out. Default false (open chat:
	// anyone with the destination hash can /join).
	Locked bool `toml:"locked"`

	// InboundStampCost is the §5.7.2 proof-of-work cost fwdsvc announces
	// in app_data element [1] and requires of inbound senders. 0 (the
	// default) announces no cost and checks nothing, which is what every
	// release before this one did: messaging the group is free, and the
	// fan-out multiplies that one free message by roster size.
	//
	// Setting it puts a CPU price on entry to the fan-out — the sender
	// grinds before we relay to N members. It is not free for us either:
	// validating one stamp builds a 768 KiB workblock, and unlike the
	// outbound grind that is work an ATTACKER triggers by messaging us.
	// The library bounds it at lxmf.MaxConcurrentStampValidations and
	// delivers unchecked past the ceiling rather than queueing, so the
	// pressure surfaces as unscored messages instead of memory.
	//
	// The cost is in leading zero bits, so difficulty DOUBLES per step:
	// 8 is about a second on a phone, 16 is minutes. Start low and read
	// the "inbound stamp:" log lines before raising it. Range
	// 0..MaxAnnouncedStampCost.
	InboundStampCost int `toml:"inbound_stamp_cost"`

	// EnforceInboundStamps drops messages that do not clear
	// InboundStampCost instead of accepting them and recording what they
	// paid. Off by default, matching upstream LXMF's _enforce_stamps and
	// the third row of §5.7.4 — cost announced, stamp missing, accept
	// anyway.
	//
	// Turn it on only after watching the "inbound stamp:" lines for a
	// while. A client that does not implement §5.7 stamps at all becomes
	// silently undeliverable to the group the moment this is set, and
	// until you have the observations you cannot tell which of your
	// members those are. Requires InboundStampCost > 0.
	EnforceInboundStamps bool `toml:"enforce_inbound_stamps"`

	// ForwardAttachments controls whether non-text LXMF fields
	// (FIELD_IMAGE = 6, FIELD_FILE_ATTACHMENTS = 5, FIELD_AUDIO = 7, …)
	// are passed through to roster recipients alongside the text body.
	// When false, every inbound non-empty fields map is dropped silently
	// and only the text body is forwarded. Default true.
	ForwardAttachments bool `toml:"forward_attachments"`

	// MaxAttachmentBytes caps the msgpack-encoded size of any single
	// allowed field value. Oversized fields are dropped (text body still
	// forwards, with a "[image not forwarded: NNN B > LIMIT B]" suffix);
	// the whole message is not lost. 0 disables the cap (not
	// recommended on LoRa). Default 1000 KiB — a forwarded attachment
	// rides a single-segment Resource transfer, which tops out near
	// 1 MiB; the default leaves headroom for LXMF framing so the
	// relayed message stays single-segment. Operators on slow links
	// may want a much lower value.
	MaxAttachmentBytes int `toml:"max_attachment_bytes"`

	// IDCacheTTL is how long fwdsvc remembers each fan-out's per-
	// recipient LXMF message_id views. The cache exists so reactions
	// (fields[0x40]), comments (0x41), continuations (0x42) and reply-to
	// (fields[0x30]) can be rewritten per recipient on fan-out — the
	// bare rebroadcast model would otherwise compute a different
	// message_id on every recipient and the binding fails. Set to 0 to
	// disable rewriting (legacy behavior: reactions show "[someone
	// reacted]" but don't land on a bubble, replies render quoted text
	// only). Default 24h covers "react to something from earlier today"
	// realistically.
	IDCacheTTL Duration `toml:"id_cache_ttl"`

	// IDCacheMax bounds the cache size (in distinct message_id keys,
	// not bubbles — a fan-out to N recipients creates N keys). LRU
	// eviction trims to this when exceeded. 0 = unbounded (only TTL
	// evicts). Default 10000 ≈ "every member sending one message every
	// few seconds for 24h on a 32-member roster fits."
	IDCacheMax int `toml:"id_cache_max"`

	// ForwardedFields is the allowlist of LXMF field keys that pass
	// through forwarding. Anything not in this list is dropped even when
	// ForwardAttachments=true — defense against a misbehaving client
	// stuffing weird keys, and an operator opt-in for new field types
	// (FIELD_FILE_ATTACHMENTS = 5, FIELD_AUDIO = 7, etc.) once those
	// clients shake out. Default [6, 48, 49, 64, 65, 66] (upstream LXMF
	// 1.0.0 field allocation, markqvist/LXMF):
	//
	//   6  FIELD_IMAGE          ["ext", bytes]
	//   48 FIELD_REPLY_TO       0x30 — raw 32-byte message_id being
	//                           replied to.
	//   49 FIELD_REPLY_QUOTE    0x31 — optional UTF-8 quote preview.
	//                           Tiny by design — usually <100 B.
	//   64 FIELD_REACTION       0x40 — tap-back reaction dict
	//                           {0x00: raw msgid, 0x01: UTF-8 content}.
	//   65 FIELD_COMMENT        0x41 — message-as-comment dict
	//                           {0x00: raw msgid}; text rides in content.
	//   66 FIELD_CONTINUATION   0x42 — message-as-continuation dict
	//                           {0x00: raw msgid}; text rides in content.
	ForwardedFields []int `toml:"forwarded_fields"`
}

// InterfaceConfig declares a single Reticulum I/O interface. Currently
// only "tcp_client" is supported (dials a TCPServerInterface peer and
// exchanges HDLC-framed packets).
type InterfaceConfig struct {
	Type    string   `toml:"type"`
	Addr    string   `toml:"addr"`
	Timeout Duration `toml:"timeout"`
}

type ReplayConfig struct {
	Count  int      `toml:"count"`
	MaxAge Duration `toml:"max_age"`

	// PinsOnJoin controls whether the pinned-message list (/pins) is sent
	// to a user on join, AFTER their history replay. Default true.
	//
	// After, not before, and that ordering is the point: the replay is a
	// wall of older traffic the joiner is scrolling past, so a pins block
	// ahead of it is the first thing pushed off the screen. Sent last it is
	// what they are looking at when the burst stops — which is the whole
	// reason issue #20 asked for pins to be played back on join rather than
	// left for the joiner to go and ask for.
	//
	// Defaulting on is safe because an empty pin list renders nothing and
	// sends nothing: a group that never pins pays exactly what it paid
	// before. Operators on a very slow segment who would rather a joiner
	// spend their budget on real traffic can set it false. The list is one
	// message regardless of how many pins it holds, and the same
	// per-destination cooldown that bounds replay bounds it too.
	PinsOnJoin bool `toml:"pins_on_join"`
}

// MeshtasticConfig configures the optional bidirectional Meshtastic channel bridge.
type MeshtasticConfig struct {
	Enabled          bool                 `toml:"enabled"`
	ChannelURL       string               `toml:"channel_url"`
	ChannelName      string               `toml:"channel_name"`
	PSK              string               `toml:"psk"`
	NodeID           string               `toml:"node_id"`
	ShortName        string               `toml:"short_name"`
	LongName         string               `toml:"long_name"`
	NodeInfoInterval Duration             `toml:"nodeinfo_interval"`
	HopLimit         int                  `toml:"hop_limit"`
	OKToMQTT         bool                 `toml:"ok_to_mqtt"`
	NameFormat       string               `toml:"name_format"`
	LongMessageMode  string               `toml:"long_message_mode"`
	MaxChunks        int                  `toml:"max_chunks"`
	ChunkDelay       Duration             `toml:"chunk_delay"`
	ExposeInInfo     bool                 `toml:"expose_in_info"`
	UDP              MeshtasticUDPConfig  `toml:"udp"`
	MQTT             MeshtasticMQTTConfig `toml:"mqtt"`

	// Resolved by normalize() for runtime consumption:
	RawPSK       []byte `toml:"-"`
	ExpandedKey  []byte `toml:"-"`
	BridgeNodeID uint32 `toml:"-"`
}

// MeshtasticUDPConfig configures the LAN UDP multicast Meshtastic transport.
type MeshtasticUDPConfig struct {
	Enabled bool   `toml:"enabled"`
	Addr    string `toml:"addr"`
	Iface   string `toml:"iface"`
}

// MeshtasticMQTTConfig configures the MQTT v3.1.1 Meshtastic transport.
type MeshtasticMQTTConfig struct {
	Enabled   bool   `toml:"enabled"`
	Broker    string `toml:"broker"`
	Username  string `toml:"username"`
	Password  string `toml:"password"`
	RootTopic string `toml:"root_topic"`
}

// Duration extends Go's time.Duration with a "d" (day) and "w" (week) suffix
// since 4-week prune windows are awkward to express in stdlib units.
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

var extDurRE = regexp.MustCompile(`^(\d+)([dw])$`)

func ParseDuration(s string) (time.Duration, error) {
	if m := extDurRE.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "d":
			return time.Duration(n) * 24 * time.Hour, nil
		case "w":
			return time.Duration(n) * 7 * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

func Load(path string) (*Config, error) {
	expanded, err := ExpandPath(path)
	if err != nil {
		return nil, err
	}
	c := defaults()
	md, err := toml.DecodeFile(expanded, c)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", expanded, err)
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	c.Warnings = unknownKeyWarnings(md.Undecoded())
	return c, nil
}

// sectionsByKey maps each key that belongs inside a [section] to the
// section names that accept it, read off the struct tags so it cannot
// drift from the fields themselves. Only single-table sections are
// included: [[interfaces]] is an array of tables, and a bare top-level
// "addr" is ambiguous enough that naming it is better than guessing.
func sectionsByKey() map[string][]string {
	out := map[string][]string{}
	ct := reflect.TypeOf(Config{})
	for i := 0; i < ct.NumField(); i++ {
		f := ct.Field(i)
		if f.Type.Kind() != reflect.Struct {
			continue
		}
		section := tagName(f)
		if section == "" {
			continue
		}
		collectSectionKeys(section, f.Type, out)
	}
	return out
}

func collectSectionKeys(section string, t reflect.Type, out map[string][]string) {
	for j := 0; j < t.NumField(); j++ {
		f := t.Field(j)
		k := tagName(f)
		if k == "" {
			continue
		}
		if f.Type.Kind() == reflect.Struct {
			collectSectionKeys(section+"."+k, f.Type, out)
			continue
		}
		out[k] = append(out[k], section)
	}
}

func tagName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
	if name == "-" {
		return ""
	}
	return name
}

// unknownKeyWarnings renders one line per key the decoder did not
// consume. The common way to get here is a section key written at the
// top level — easy to do because admins/mods must be top-level and the
// file invites you to add things near them — so that case names the
// section the key belongs in.
func unknownKeyWarnings(keys []toml.Key) []string {
	if len(keys) == 0 {
		return nil
	}
	homes := sectionsByKey()
	var out []string
	for _, k := range keys {
		msg := fmt.Sprintf("config key %q is not recognised and has no effect", k.String())
		if len(k) == 1 {
			if secs := homes[k[0]]; len(secs) > 0 {
				msg += fmt.Sprintf(" (it belongs under [%s] — keys after a [section] header, or before the first one, are scoped by TOML to that position)", strings.Join(secs, "] or ["))
			}
		}
		out = append(out, msg)
	}
	return out
}

func defaults() *Config {
	return &Config{
		Service: ServiceConfig{
			DisplayName:      "Group Chat - send /join",
			IdentityPath:     "~/.fwdsvc/identity",
			StatePath:        "~/.fwdsvc/state.json",
			HistoryPath:      "~/.fwdsvc/history.json",
			PruneAfter:       Duration(4 * 7 * 24 * time.Hour),
			PruneSilentAfter: Duration(6 * 7 * 24 * time.Hour),
			PruneInterval:    Duration(1 * time.Hour),
			AnnounceInterval:   Duration(10 * time.Minute),
			MaxInboundChars:    500,
			MaxMembers:         DefaultMaxMembers,
			DedupWindow:        Duration(1 * time.Hour),
			ForwardAttachments: true,
			MaxAttachmentBytes: 1000 * 1024,
			ForwardedFields:    []int{6, 48, 49, 64, 65, 66},
			IDCacheTTL:         Duration(24 * time.Hour),
			IDCacheMax:         10000,
		},
		Replay: ReplayConfig{
			Count:      100,
			MaxAge:     Duration(7 * 24 * time.Hour),
			PinsOnJoin: true,
		},
		Propagation: PropagationConfig{
			Enabled:        false,
			Mode:           PropagationModeFallback,
			DirectAttempts: 3,
		},
		Meshtastic: MeshtasticConfig{
			Enabled:          false,
			ShortName:        "RNS",
			NodeInfoInterval: Duration(30 * time.Minute),
			HopLimit:         3,
			OKToMQTT:         true,
			NameFormat:       "short",
			LongMessageMode:  "chunk",
			MaxChunks:        3,
			ChunkDelay:       Duration(2 * time.Second),
			ExposeInInfo:     true,
			UDP: MeshtasticUDPConfig{
				Addr: meshtastic.DefaultUDPAddr,
			},
			MQTT: MeshtasticMQTTConfig{
				RootTopic: meshtastic.DefaultMQTTRootTopic,
			},
		},
	}
}

func (c *Config) normalize() error {
	for _, p := range []*string{
		&c.Service.IdentityPath,
		&c.Service.StatePath,
		&c.Service.HistoryPath,
		&c.Service.LogPath,
	} {
		ex, err := ExpandPath(*p)
		if err != nil {
			return err
		}
		*p = ex
	}

	if strings.TrimSpace(c.Service.DisplayName) == "" {
		return fmt.Errorf("service.display_name must not be empty")
	}
	if c.Service.PruneInterval.Std() <= 0 {
		return fmt.Errorf("service.prune_interval must be positive")
	}
	if c.Service.PruneAfter.Std() <= 0 {
		return fmt.Errorf("service.prune_after must be positive")
	}
	if c.Service.PruneSilentAfter.Std() < 0 {
		return fmt.Errorf("service.prune_silent_after must be >= 0 (0 disables)")
	}
	// Refuse a typo rather than fall back to a default: "warnings" quietly
	// becoming info would be the opposite of what the operator asked for,
	// and they would only notice when the journal stayed loud.
	if strings.TrimSpace(c.Service.LogLevel) == "" {
		c.Service.LogLevelValue = rns.LogInfo
	} else {
		lvl, err := rns.ParseLogLevel(c.Service.LogLevel)
		if err != nil {
			return fmt.Errorf("service.log_level: %w", err)
		}
		c.Service.LogLevelValue = lvl
	}
	if c.Service.AnnounceInterval.Std() <= 0 {
		return fmt.Errorf("service.announce_interval must be positive")
	}
	if c.Service.MaxInboundChars < 0 {
		return fmt.Errorf("service.max_inbound_chars must be >= 0")
	}
	if c.Service.MaxMembers < 0 {
		return fmt.Errorf("service.max_members must be >= 0")
	}
	if c.Service.DedupWindow.Std() < 0 {
		return fmt.Errorf("service.dedup_window must be >= 0 (0 disables)")
	}
	if c.Service.MaxAttachmentBytes < 0 {
		return fmt.Errorf("service.max_attachment_bytes must be >= 0")
	}
	if c.Service.InboundStampCost < 0 || c.Service.InboundStampCost > MaxAnnouncedStampCost {
		return fmt.Errorf("service.inbound_stamp_cost must be 0..%d (0 disables)", MaxAnnouncedStampCost)
	}
	// Enforcing against a cost of zero would drop nothing while reading
	// like a working spam defense, so it is refused in config rather
	// than being a silent no-op at runtime.
	if c.Service.EnforceInboundStamps && c.Service.InboundStampCost == 0 {
		return fmt.Errorf("service.enforce_inbound_stamps requires service.inbound_stamp_cost > 0")
	}
	if c.Service.IDCacheTTL.Std() < 0 {
		return fmt.Errorf("service.id_cache_ttl must be >= 0 (0 disables)")
	}
	if c.Service.IDCacheMax < 0 {
		return fmt.Errorf("service.id_cache_max must be >= 0")
	}
	for i, k := range c.Service.ForwardedFields {
		if k < 0 {
			return fmt.Errorf("service.forwarded_fields[%d]: field key must be >= 0", i)
		}
		// 251/252 are the relay's own attribution fields (originator
		// identity + verified source hash), stamped by rewrite.go on
		// outbound reactions. Forwarding attacker-supplied values would
		// let a non-reaction message carry a forged attribution that
		// cooperating clients render as someone else — so they are
		// refused in config rather than silently dropped at runtime.
		if k == fieldOriginatorIdentity || k == fieldOriginatorHash {
			return fmt.Errorf("service.forwarded_fields[%d]: field %d is reserved for relay attribution and must not be forwarded", i, k)
		}
	}
	if s := strings.TrimSpace(c.Service.IdentityB64); s != "" {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("service.identity_b64: not valid base64: %w", err)
		}
		if len(raw) != identityPrivateKeyLen {
			return fmt.Errorf("service.identity_b64: must decode to %d bytes (got %d)",
				identityPrivateKeyLen, len(raw))
		}
		c.Service.IdentityB64 = s
	}
	for i, iface := range c.Interfaces {
		if iface.Type != "tcp_client" {
			return fmt.Errorf("interfaces[%d]: only tcp_client is supported, got %q", i, iface.Type)
		}
		if strings.TrimSpace(iface.Addr) == "" {
			return fmt.Errorf("interfaces[%d]: addr is required", i)
		}
	}
	if c.Replay.Count < 0 {
		return fmt.Errorf("replay.count must be >= 0")
	}
	if c.Replay.MaxAge.Std() < 0 {
		return fmt.Errorf("replay.max_age must be >= 0")
	}

	c.Propagation.Mode = strings.ToLower(strings.TrimSpace(c.Propagation.Mode))
	if c.Propagation.Mode == "" {
		c.Propagation.Mode = PropagationModeFallback
	}
	if c.Propagation.Mode != PropagationModeFallback && c.Propagation.Mode != PropagationModeAlways {
		return fmt.Errorf("propagation.mode must be %q or %q, got %q",
			PropagationModeFallback, PropagationModeAlways, c.Propagation.Mode)
	}
	if c.Propagation.DirectAttempts < 0 {
		return fmt.Errorf("propagation.direct_attempts must be >= 1 (or unset for the default %d), got %d",
			DefaultPropagationDirectAttempts, c.Propagation.DirectAttempts)
	}
	if c.Propagation.DirectAttempts == 0 {
		c.Propagation.DirectAttempts = DefaultPropagationDirectAttempts
	}
	c.Propagation.Node = strings.ToLower(strings.TrimSpace(c.Propagation.Node))
	if c.Propagation.Node != "" {
		raw, err := hex.DecodeString(c.Propagation.Node)
		if err != nil {
			return fmt.Errorf("propagation.node: %q is not valid hex: %w", c.Propagation.Node, err)
		}
		if len(raw) != identityHashLen {
			return fmt.Errorf("propagation.node: %q must decode to %d bytes (got %d)",
				c.Propagation.Node, identityHashLen, len(raw))
		}
	}

	c.Admins = normalizeHashList(c.Admins)
	c.Mods = normalizeHashList(c.Mods)
	if err := validateHashes("admins", c.Admins); err != nil {
		return err
	}
	if err := validateHashes("mods", c.Mods); err != nil {
		return err
	}
	if err := c.normalizeMeshtastic(); err != nil {
		return err
	}
	return nil
}

func (c *Config) normalizeMeshtastic() error {
	m := &c.Meshtastic
	m.ChannelURL = strings.TrimSpace(m.ChannelURL)
	m.ChannelName = strings.TrimSpace(m.ChannelName)
	m.PSK = strings.TrimSpace(m.PSK)
	m.NodeID = strings.TrimSpace(m.NodeID)
	m.ShortName = strings.TrimSpace(m.ShortName)
	m.LongName = strings.TrimSpace(m.LongName)

	var urlPSK []byte
	hasURLPSK := false
	if m.ChannelURL != "" {
		urlName, pskBytes, err := meshtastic.ParseChannelURL(m.ChannelURL)
		if err != nil {
			return fmt.Errorf("meshtastic.channel_url: %w", err)
		}
		if m.ChannelName == "" {
			m.ChannelName = urlName
		}
		urlPSK = pskBytes
		hasURLPSK = true
	}

	switch {
	case m.PSK != "":
		raw, exp, err := meshtastic.ParsePSK(m.PSK)
		if err != nil {
			return err
		}
		m.RawPSK = raw
		m.ExpandedKey = exp
	case hasURLPSK:
		exp, err := meshtastic.ExpandPSK(urlPSK)
		if err != nil {
			return fmt.Errorf("meshtastic.channel_url psk: %w", err)
		}
		m.RawPSK = urlPSK
		m.ExpandedKey = exp
	default:
		raw, exp, err := meshtastic.ParsePSK("default")
		if err != nil {
			return err
		}
		m.RawPSK = raw
		m.ExpandedKey = exp
	}

	if m.NodeID != "" {
		id, err := meshtastic.ParseNodeID(m.NodeID)
		if err != nil {
			return fmt.Errorf("meshtastic.node_id: %w", err)
		}
		m.BridgeNodeID = id
	}

	if m.ShortName == "" {
		m.ShortName = "RNS"
	}
	if len(m.ShortName) > 4 {
		return fmt.Errorf("meshtastic.short_name %q must be at most 4 bytes (got %d)", m.ShortName, len(m.ShortName))
	}
	if m.LongName == "" {
		m.LongName = c.Service.DisplayName
	}
	if m.NodeInfoInterval.Std() < 0 {
		return fmt.Errorf("meshtastic.nodeinfo_interval must be >= 0 (0 disables)")
	}
	if m.HopLimit == 0 {
		m.HopLimit = 3
	}
	if m.HopLimit < 1 || m.HopLimit > 7 {
		return fmt.Errorf("meshtastic.hop_limit must be 1..7 (got %d)", m.HopLimit)
	}

	m.NameFormat = strings.ToLower(strings.TrimSpace(m.NameFormat))
	if m.NameFormat == "" {
		m.NameFormat = "short"
	}
	if m.NameFormat != "short" && m.NameFormat != "long" {
		return fmt.Errorf("meshtastic.name_format must be \"short\" or \"long\", got %q", m.NameFormat)
	}

	m.LongMessageMode = strings.ToLower(strings.TrimSpace(m.LongMessageMode))
	if m.LongMessageMode == "" {
		m.LongMessageMode = "chunk"
	}
	if m.LongMessageMode != "chunk" && m.LongMessageMode != "truncate" {
		return fmt.Errorf("meshtastic.long_message_mode must be \"chunk\" or \"truncate\", got %q", m.LongMessageMode)
	}
	if m.MaxChunks < 0 {
		return fmt.Errorf("meshtastic.max_chunks must be >= 1")
	}
	if m.MaxChunks == 0 {
		m.MaxChunks = 3
	}
	if m.ChunkDelay.Std() < 0 {
		return fmt.Errorf("meshtastic.chunk_delay must be >= 0")
	}

	m.UDP.Addr = strings.TrimSpace(m.UDP.Addr)
	if m.UDP.Addr == "" {
		m.UDP.Addr = meshtastic.DefaultUDPAddr
	}
	m.UDP.Iface = strings.TrimSpace(m.UDP.Iface)

	m.MQTT.Broker = strings.TrimSpace(m.MQTT.Broker)
	m.MQTT.RootTopic = strings.TrimSpace(m.MQTT.RootTopic)
	if m.MQTT.RootTopic == "" {
		m.MQTT.RootTopic = meshtastic.DefaultMQTTRootTopic
	}

	if hasMQTTTopicWildcardOrControl(m.ChannelName, true) {
		return fmt.Errorf("meshtastic.channel_name %q must not contain '/', '+', '#', or control characters", m.ChannelName)
	}
	if hasMQTTTopicWildcardOrControl(m.MQTT.RootTopic, false) {
		return fmt.Errorf("meshtastic.mqtt.root_topic %q must not contain '+', '#', or control characters", m.MQTT.RootTopic)
	}

	if m.Enabled {
		if m.ChannelName == "" {
			return fmt.Errorf("meshtastic.channel_name (or channel_url) is required when meshtastic.enabled is true")
		}
		if !m.UDP.Enabled && !m.MQTT.Enabled {
			return fmt.Errorf("meshtastic: enable at least one transport ([meshtastic.udp] or [meshtastic.mqtt])")
		}
		if m.MQTT.Enabled && m.MQTT.Broker == "" {
			return fmt.Errorf("meshtastic.mqtt.broker is required when meshtastic.mqtt.enabled is true")
		}
	}
	return nil
}

func hasMQTTTopicWildcardOrControl(s string, forbidSlash bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '+' || c == '#' || (forbidSlash && c == '/') {
			return true
		}
	}
	return false
}

func normalizeHashList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func validateHashes(field string, hashes []string) error {
	for _, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("%s: %q is not valid hex: %w", field, h, err)
		}
		if len(raw) != identityHashLen {
			return fmt.Errorf("%s: %q must decode to %d bytes (got %d)", field, h, identityHashLen, len(raw))
		}
	}
	return nil
}

func ExpandPath(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return filepath.Clean(p), nil
}

// IsAdmin returns true if the lowercase hex hash is in the configured admins list.
func (c *Config) IsAdmin(hashHex string) bool {
	return contains(c.Admins, strings.ToLower(hashHex))
}

// IsMod returns true if the lowercase hex hash is in the configured mods list.
func (c *Config) IsMod(hashHex string) bool {
	return contains(c.Mods, strings.ToLower(hashHex))
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
