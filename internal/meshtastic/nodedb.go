package meshtastic

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NodeEntry holds learned identity metadata for a Meshtastic node.
type NodeEntry struct {
	NodeID    uint32    `json:"node_id"`
	ShortName string    `json:"short_name,omitempty"`
	LongName  string    `json:"long_name,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type nodeDBFile struct {
	Nodes   map[string]*NodeEntry `json:"nodes"`
	Banlist []string              `json:"banlist,omitempty"`
}

// NodeDB persists learned Meshtastic node names and banned Meshtastic node IDs
// alongside fwdsvc's state file (meshnodes.json).
type NodeDB struct {
	mu      sync.Mutex
	path    string
	nodes   map[string]*NodeEntry // key: lowercase 8-char hex
	banlist map[string]struct{}   // key: lowercase 8-char hex
	dirty   bool
}

// NewNodeDB loads or creates a NodeDB backed by path (in-memory only if path == "").
func NewNodeDB(path string) (*NodeDB, error) {
	db := &NodeDB{
		path:    path,
		nodes:   make(map[string]*NodeEntry),
		banlist: make(map[string]struct{}),
	}
	if path != "" {
		if err := db.load(); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *NodeDB) load() error {
	data, err := os.ReadFile(db.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var f nodeDBFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse meshnodes: %w", err)
	}
	for k, e := range f.Nodes {
		if e == nil {
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(k, "!"))
		if e.NodeID == 0 {
			if id, err := ParseNodeID(key); err == nil {
				e.NodeID = id
			}
		}
		db.nodes[FormatNodeHex(e.NodeID)] = e
	}
	for _, b := range f.Banlist {
		id, err := ParseNodeID(b)
		if err != nil {
			continue
		}
		db.banlist[FormatNodeHex(id)] = struct{}{}
	}
	return nil
}

// FormatNodeHex formats nodeID as lowercase 8-character hex (without leading '!').
func FormatNodeHex(nodeID uint32) string {
	return fmt.Sprintf("%08x", nodeID)
}

// FormatNodeBang formats nodeID as "!xxxxxxxx".
func FormatNodeBang(nodeID uint32) string {
	return fmt.Sprintf("!%08x", nodeID)
}

// ParseNodeID parses a 32-bit Meshtastic node ID in hex ("!a1b2c3d4" or "a1b2c3d4").
func ParseNodeID(s string) (uint32, error) {
	clean := strings.ToLower(strings.TrimSpace(s))
	clean = strings.TrimPrefix(clean, "!")
	if len(clean) == 0 || len(clean) > 8 {
		return 0, fmt.Errorf("invalid Meshtastic node ID %q (expected !xxxxxxxx hex)", s)
	}
	v, err := strconv.ParseUint(clean, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid Meshtastic node ID %q: %w", s, err)
	}
	if v == 0 || v == uint64(BroadcastAddr) {
		return 0, fmt.Errorf("Meshtastic node ID %q is reserved", s)
	}
	return uint32(v), nil
}

// SyntheticLXMFHash returns a deterministic 16-byte synthetic destination hash
// ("meshtastic\x00\x00" || bigEndian(nodeID)) for Meshtastic->LXMF attribution
// in history logs and FIELD_CUSTOM_DATA reaction stamps.
func SyntheticLXMFHash(nodeID uint32) []byte {
	out := make([]byte, 16)
	copy(out[:12], "meshtastic\x00\x00")
	binary.BigEndian.PutUint32(out[12:16], nodeID)
	return out
}

// UpdateUser records short/long names learned from an inbound NODEINFO_APP packet.
func (db *NodeDB) UpdateUser(nodeID uint32, shortName, longName string, seenAt time.Time) {
	if nodeID == 0 || nodeID == BroadcastAddr {
		return
	}
	key := FormatNodeHex(nodeID)
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.nodes[key]
	if !ok {
		e = &NodeEntry{NodeID: nodeID}
		db.nodes[key] = e
	}
	if shortName != "" {
		e.ShortName = shortName
	}
	if longName != "" {
		e.LongName = longName
	}
	if seenAt.After(e.LastSeen) {
		e.LastSeen = seenAt
	}
	if db.path != "" {
		db.dirty = true
	}
}

// Touch updates LastSeen for a node that sent a packet on the channel.
func (db *NodeDB) Touch(nodeID uint32, seenAt time.Time) {
	if nodeID == 0 || nodeID == BroadcastAddr {
		return
	}
	key := FormatNodeHex(nodeID)
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.nodes[key]
	if !ok {
		e = &NodeEntry{NodeID: nodeID}
		db.nodes[key] = e
	}
	if seenAt.After(e.LastSeen) {
		e.LastSeen = seenAt
		if db.path != "" {
			db.dirty = true
		}
	}
}

// Get returns the NodeEntry for nodeID if known.
func (db *NodeDB) Get(nodeID uint32) (NodeEntry, bool) {
	key := FormatNodeHex(nodeID)
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.nodes[key]
	if !ok {
		return NodeEntry{}, false
	}
	return *e, true
}

// FormatSenderLabel formats a Meshtastic sender for LXMF attribution:
// "M:<ShortName>" (or "M:<LongName>" when longFormat is true) if learned,
// falling back to "M:!<last4hex>".
func (db *NodeDB) FormatSenderLabel(nodeID uint32, longFormat bool) string {
	e, ok := db.Get(nodeID)
	if ok {
		raw := e.ShortName
		if longFormat && e.LongName != "" {
			raw = e.LongName
		} else if raw == "" {
			raw = e.LongName
		}
		if clean := sanitizeMeshName(raw); clean != "" {
			return "M:" + clean
		}
	}
	return fmt.Sprintf("M:!%04x", nodeID&0xFFFF)
}

func sanitizeMeshName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			continue
		case r == '[' || r == ']':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// RecentNodes returns up to limit recently seen nodes ordered newest first.
func (db *NodeDB) RecentNodes(limit int) []NodeEntry {
	db.mu.Lock()
	out := make([]NodeEntry, 0, len(db.nodes))
	for _, e := range db.nodes {
		out = append(out, *e)
	}
	db.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].NodeID < out[j].NodeID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// IsBanned reports whether nodeID is in the Meshtastic banlist.
func (db *NodeDB) IsBanned(nodeID uint32) bool {
	key := FormatNodeHex(nodeID)
	db.mu.Lock()
	_, ok := db.banlist[key]
	db.mu.Unlock()
	return ok
}

// Ban adds a Meshtastic node (specified by "!xxxxxxxx" or a >=4 hex prefix of a
// known node) to the banlist and persists immediately.
func (db *NodeDB) Ban(spec string) (uint32, string, error) {
	clean := strings.ToLower(strings.TrimSpace(spec))
	clean = strings.TrimPrefix(clean, "!")
	if len(clean) < 4 || len(clean) > 8 || !isHexDigits(clean) {
		return 0, "", fmt.Errorf("invalid Meshtastic node spec %q (use !xxxxxxxx or >=4 hex chars)", spec)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	var targetKey string
	var targetID uint32
	if len(clean) == 8 {
		id, err := ParseNodeID(clean)
		if err != nil {
			return 0, "", err
		}
		targetID = id
		targetKey = FormatNodeHex(id)
	} else {
		var matches []string
		for k := range db.nodes {
			if strings.HasPrefix(k, clean) {
				matches = append(matches, k)
			}
		}
		switch len(matches) {
		case 0:
			return 0, "", fmt.Errorf("no known Meshtastic node matches !%s (give full 8 hex chars to pre-ban)", clean)
		case 1:
			targetKey = matches[0]
			targetID, _ = ParseNodeID(targetKey)
		default:
			sort.Strings(matches)
			return 0, "", fmt.Errorf("!%s is ambiguous: !%s", clean, strings.Join(matches, ", !"))
		}
	}

	db.banlist[targetKey] = struct{}{}
	label := "!" + targetKey
	if e, ok := db.nodes[targetKey]; ok {
		if name := sanitizeMeshName(e.ShortName); name != "" {
			label = fmt.Sprintf("%s (!%s)", name, targetKey)
		}
	}
	if err := db.persistLocked(); err != nil {
		return 0, "", err
	}
	return targetID, label, nil
}

// Unban removes a Meshtastic node (full !xxxxxxxx or >=4 hex prefix in banlist).
func (db *NodeDB) Unban(spec string) (uint32, bool, error) {
	clean := strings.ToLower(strings.TrimSpace(spec))
	clean = strings.TrimPrefix(clean, "!")
	if len(clean) < 4 || len(clean) > 8 || !isHexDigits(clean) {
		return 0, false, fmt.Errorf("invalid Meshtastic node spec %q (use !xxxxxxxx or >=4 hex chars)", spec)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if len(clean) == 8 {
		id, err := ParseNodeID(clean)
		if err != nil {
			return 0, false, err
		}
		key := FormatNodeHex(id)
		if _, ok := db.banlist[key]; !ok {
			return id, false, nil
		}
		delete(db.banlist, key)
		return id, true, db.persistLocked()
	}

	var matches []string
	for k := range db.banlist {
		if strings.HasPrefix(k, clean) {
			matches = append(matches, k)
		}
	}
	switch len(matches) {
	case 0:
		return 0, false, nil
	case 1:
		id, _ := ParseNodeID(matches[0])
		delete(db.banlist, matches[0])
		return id, true, db.persistLocked()
	default:
		sort.Strings(matches)
		return 0, false, fmt.Errorf("!%s matches multiple banned nodes: !%s", clean, strings.Join(matches, ", !"))
	}
}

// Banlist returns a sorted slice of banned "!xxxxxxxx" strings.
func (db *NodeDB) Banlist() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	out := make([]string, 0, len(db.banlist))
	for k := range db.banlist {
		out = append(out, "!"+k)
	}
	sort.Strings(out)
	return out
}

// Flush writes deferred node-database changes to disk.
func (db *NodeDB) Flush() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty {
		return nil
	}
	return db.persistLocked()
}

func (db *NodeDB) persistLocked() error {
	if db.path == "" {
		db.dirty = false
		return nil
	}
	db.dirty = false
	if err := os.MkdirAll(filepath.Dir(db.path), 0o700); err != nil {
		return err
	}
	ban := make([]string, 0, len(db.banlist))
	for k := range db.banlist {
		ban = append(ban, k)
	}
	sort.Strings(ban)

	data, err := json.MarshalIndent(nodeDBFile{
		Nodes:   db.nodes,
		Banlist: ban,
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(db.path, data, 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func isHexDigits(s string) bool {
	if s == "" {
		return false
	}
	_, err := hex.DecodeString(paddedEvenHex(s))
	return err == nil
}

func paddedEvenHex(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}
