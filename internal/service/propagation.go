package service

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

var lxmfPropagationNameHash = rns.NameHash(lxmf.PropagationFullName())

// propagationTracker watches lxmf.propagation announces (SPEC §5.8.5)
// and answers "which propagation node should outbound store-and-forward
// submissions go to right now?".
//
// Selection policy: a pinned node from config always wins — even before
// its first announce is heard, so the send path can surface
// ErrPropagationNodeUnknown and trigger a path request rather than
// silently using a different node than the operator chose.
//
// With no pin, candidates must be USABLE (accepting messages, and
// announcing parameters we can actually satisfy — see acceptableNode)
// and FRESH (heard within nodeStaleAfter). Among those, the node known
// LONGEST wins. Announces are unauthenticated and free, so preferring
// the most recently heard node — the original policy — let an attacker
// announcing once per second deterministically seize the role from
// honest nodes and silently blackhole every store-and-forward message.
type propagationTracker struct {
	logger *logging.Logger
	pinned []byte // nil when auto-discovering
	now    func() time.Time

	mu          sync.Mutex
	nodes       map[string]*propagationNodeState // dest_hash hex → state
	onNodeReady func()                           // optional non-blocking wake for inbound sync
}

type propagationNodeState struct {
	destHash        []byte
	firstHeard      time.Time
	lastHeard       time.Time
	enabled         bool
	stampCost       int
	transferLimitKB int64
	// usable is false when the announced parameters make the node
	// unusable (see acceptableNode). Recorded rather than discarded so
	// the operator log explains why a node is being skipped.
	usable bool
}

// Node-selection policy constants.
const (
	// maxTrackedNodes bounds the discovered-node map. Announces are
	// unauthenticated, so without a cap an attacker cycling identities
	// grows it without limit — and Current() scans it per submission.
	maxTrackedNodes = 256

	// nodeStaleAfter drops a node that has not re-announced. Without it
	// a node heard once, hours ago, stays selectable forever.
	nodeStaleAfter = 30 * time.Minute

	// minTransferLimitKB rejects nodes advertising an implausibly small
	// per-transfer cap — a hostile node can otherwise announce 1 KB and
	// cause every submission to fail the size check.
	minTransferLimitKB = 16
)

func newPropagationTracker(logger *logging.Logger, pinned []byte) *propagationTracker {
	return &propagationTracker{
		logger: logger,
		pinned: append([]byte(nil), pinned...),
		now:    time.Now,
		nodes:  map[string]*propagationNodeState{},
	}
}

// AspectMatch implements rns.AnnounceHandler — only lxmf.propagation
// announces reach OnAnnounce.
func (t *propagationTracker) AspectMatch(nameHash []byte) bool {
	return bytes.Equal(nameHash, lxmfPropagationNameHash)
}

// normalizePropagationAppData converts 8-element LXMF propagation announce
// app_data arrays (which append an extension element) into the 7-element form
// accepted by reticulum-go's ParsePropagationNodeAppData.
func normalizePropagationAppData(appData []byte) ([]byte, bool) {
	var elems []msgpack.RawMessage
	if err := msgpack.Unmarshal(appData, &elems); err == nil && len(elems) == 8 {
		normalized, err := msgpack.Marshal(elems[:7])
		if err == nil {
			return normalized, true
		}
	}
	return appData, false
}

// parsePropagationAnnounceAppData accepts the 7-element LXMF propagation
// announce format and the newer format that appends an eighth extension
// field. The tracker only needs the original seven fields; the extension
// is intentionally ignored so newer nodes remain interoperable with this
// version of reticulum-go.
func parsePropagationAnnounceAppData(appData []byte) (*lxmf.PropagationNodeInfo, error) {
	normalized, _ := normalizePropagationAppData(appData)
	return lxmf.ParsePropagationNodeAppData(normalized)
}

// setOnNodeReady registers a non-blocking callback fired when the pinned
// node announces or an auto-discovered usable node is heard. Used by the
// inbound propagation syncer to wake early when it was waiting for a node.
func (t *propagationTracker) setOnNodeReady(fn func()) {
	t.mu.Lock()
	t.onNodeReady = fn
	t.mu.Unlock()
}

// Seed populates the tracker from persisted announce-cache entries
// (announces.json) so auto-discovery can resume immediately after a quick
// restart instead of waiting for the next propagation announce cycle.
// Entries older than nodeStaleAfter are ignored to preserve freshness.
func (t *propagationTracker) Seed(entries []*rns.KnownIdentity) int {
	now := t.now()
	added := 0
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range entries {
		if e == nil || len(e.DestHash) != rns.IdentityHashLen || !bytes.Equal(e.NameHash, lxmfPropagationNameHash) {
			continue
		}
		if now.Sub(e.LastSeen) > nodeStaleAfter {
			continue
		}
		info, err := parsePropagationAnnounceAppData(e.AppData)
		if err != nil {
			continue
		}
		usable, _ := acceptableNode(info)
		key := hex.EncodeToString(e.DestHash)
		if _, exists := t.nodes[key]; exists {
			continue
		}
		t.evictStaleLocked(now)
		t.nodes[key] = &propagationNodeState{
			destHash:        append([]byte(nil), e.DestHash...),
			firstHeard:      e.LastSeen,
			lastHeard:       e.LastSeen,
			enabled:         info.Enabled,
			stampCost:       info.StampCost,
			transferLimitKB: info.PerTransferLimitKB,
			usable:          usable,
		}
		added++
	}
	return added
}

// OnAnnounce parses the §5.8.5 app_data and records the node. Malformed
// app_data is logged and skipped — a node we can't parse is a node we
// can't negotiate stamps/limits with, so it is never a send candidate.
func (t *propagationTracker) OnAnnounce(a *rns.Announce) {
	isPinned := len(t.pinned) > 0 && bytes.Equal(a.DestHash, t.pinned)
	info, err := parsePropagationAnnounceAppData(a.AppData)
	if err != nil {
		// Debug, not info: unlike the cases below this one has no
		// first-heard check, so it fires on EVERY announce from a node
		// whose app_data we cannot parse. That is a stranger's bytes on a
		// public mesh — not actionable, and at info a node re-announcing
		// every second would be one log line per second for as long as it
		// keeps doing so.
		t.logger.Debugf("propagation: ignoring node %x: %v", a.DestHash[:4], err)
		// For a pinned node, Transport.known already cached its public key
		// before OnAnnounce ran, so inbound /get retrieval can still open a
		// link even if app_data was unparseable.
		if isPinned {
			t.notifyNodeReady()
		}
		return
	}
	key := hex.EncodeToString(a.DestHash)
	now := t.now()
	usable, reason := acceptableNode(info)

	t.mu.Lock()
	prev := t.nodes[key]
	firstHeard := now
	if prev != nil {
		firstHeard = prev.firstHeard
	}
	if prev == nil {
		t.evictStaleLocked(now)
	}
	t.nodes[key] = &propagationNodeState{
		destHash:        append([]byte(nil), a.DestHash...),
		firstHeard:      firstHeard,
		lastHeard:       now,
		enabled:         info.Enabled,
		stampCost:       info.StampCost,
		transferLimitKB: info.PerTransferLimitKB,
		usable:          usable,
	}
	cb := t.onNodeReady
	t.mu.Unlock()

	if cb != nil && (isPinned || (len(t.pinned) == 0 && usable)) {
		cb()
	}

	switch {
	case prev == nil && !usable:
		t.logger.Infof("propagation: ignoring node %s — %s (stamp_cost=%d transfer_limit=%dKB)",
			key[:8], reason, info.StampCost, info.PerTransferLimitKB)
	case prev == nil:
		t.logger.Infof("propagation: discovered node %s (accepting=%v stamp_cost=%d transfer_limit=%dKB)",
			key[:8], info.Enabled, info.StampCost, info.PerTransferLimitKB)
	case prev.enabled != info.Enabled:
		t.logger.Infof("propagation: node %s now accepting=%v", key[:8], info.Enabled)
	case prev.usable != usable && !usable:
		t.logger.Infof("propagation: node %s no longer usable — %s", key[:8], reason)
	}
}

func (t *propagationTracker) notifyNodeReady() {
	t.mu.Lock()
	cb := t.onNodeReady
	t.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// acceptableNode decides at SELECTION time whether a node's announced
// parameters are workable.
//
// WHY THIS IS NOT DEFERRED TO SEND TIME: every one of these values is
// set by whoever sent the announce, and previously an unusable value
// was only discovered inside SendPropagated — where it surfaces as an
// error that is neither errNoPropagationNode nor a transient failure,
// so the queue burned the retry budget and DROPPED the message. A
// hostile node could therefore destroy all fallback mail by announcing
// stamp_cost=200 or per_transfer_limit=1. Filtering here turns "lose
// the message" into "pick a different node".
func acceptableNode(info *lxmf.PropagationNodeInfo) (bool, string) {
	if !info.Enabled {
		return false, "not accepting messages"
	}
	if info.StampCost > lxmf.MaxPropagationStampCost {
		return false, fmt.Sprintf("demands stamp_cost %d above local limit %d",
			info.StampCost, lxmf.MaxPropagationStampCost)
	}
	if info.PerTransferLimitKB > 0 && info.PerTransferLimitKB < minTransferLimitKB {
		return false, fmt.Sprintf("per-transfer limit %dKB is implausibly small",
			info.PerTransferLimitKB)
	}
	return true, ""
}

// evictStaleLocked prunes stale entries and, if still at capacity, the
// least-recently-heard node. Callers must hold t.mu.
func (t *propagationTracker) evictStaleLocked(now time.Time) {
	for k, n := range t.nodes {
		if now.Sub(n.lastHeard) > nodeStaleAfter {
			delete(t.nodes, k)
		}
	}
	for len(t.nodes) >= maxTrackedNodes {
		var oldestKey string
		var oldestAt time.Time
		for k, n := range t.nodes {
			if oldestKey == "" || n.lastHeard.Before(oldestAt) {
				oldestKey, oldestAt = k, n.lastHeard
			}
		}
		if oldestKey == "" {
			return
		}
		delete(t.nodes, oldestKey)
	}
}

// Current returns the destination hash of the node outbound submissions
// should use, or nil when none is available. See type docs for policy.
func (t *propagationTracker) Current() []byte {
	if len(t.pinned) > 0 {
		return append([]byte(nil), t.pinned...)
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	// Selection policy: among nodes that are usable AND currently fresh,
	// prefer the one we have known LONGEST.
	//
	// Most-recently-heard (the previous policy) is trivially gameable:
	// announces are unauthenticated and free, so an attacker announcing
	// once per second deterministically beat honest nodes announcing on
	// a multi-minute schedule, seizing the role and silently blackholing
	// all fallback mail. Longest-known inverts that — an attacker must
	// out-persist every established node rather than out-shout it — and
	// the freshness requirement still drops nodes that go away.
	var best *propagationNodeState
	for _, n := range t.nodes {
		if !n.usable || now.Sub(n.lastHeard) > nodeStaleAfter {
			continue
		}
		if best == nil || n.firstHeard.Before(best.firstHeard) {
			best = n
		}
	}
	if best == nil {
		return nil
	}
	return append([]byte(nil), best.destHash...)
}

// Compile-time guard: propagationTracker implements rns.AnnounceHandler.
var _ rns.AnnounceHandler = (*propagationTracker)(nil)
