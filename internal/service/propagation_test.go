package service

import (
	"bytes"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-go/rns"
)

func pnAnnounce(t *testing.T, destByte byte, enabled bool) *rns.Announce {
	t.Helper()
	appData, err := msgpack.Marshal([]any{
		false, time.Now().Unix(), enabled, 256, 256,
		[]any{0, 0, 0}, map[any]any{}, "future-extension",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rns.Announce{
		DestHash: bytes.Repeat([]byte{destByte}, 16),
		NameHash: lxmfPropagationNameHash,
		AppData:  appData,
	}
}

func pnAppData(t *testing.T, enabled bool, transferLimitKB, stampCost int) []byte {
	t.Helper()
	data, err := msgpack.Marshal([]any{
		false, time.Now().Unix(), enabled, transferLimitKB, transferLimitKB,
		[]any{stampCost, 0, 0}, map[any]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestTracker(pinned []byte) *propagationTracker {
	return newPropagationTracker(logging.Discard(), pinned)
}

func TestTrackerAspectMatch(t *testing.T) {
	tr := newTestTracker(nil)
	if !tr.AspectMatch(lxmfPropagationNameHash) {
		t.Error("lxmf.propagation name hash should match")
	}
	if tr.AspectMatch(lxmfDeliveryNameHash) {
		t.Error("lxmf.delivery name hash should NOT match")
	}
}

func TestTrackerPrefersLongestKnownNode(t *testing.T) {
	// Selection must NOT be "most recently heard": announces are free
	// and unauthenticated, so that policy let an attacker announcing
	// rapidly seize the role from established nodes. Longest-known wins.
	tr := newTestTracker(nil)
	if tr.Current() != nil {
		t.Fatal("empty tracker should have no current node")
	}

	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	tr.OnAnnounce(pnAnnounce(t, 0xaa, true)) // established node
	clock = base.Add(time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true)) // newcomer

	// Newcomer announces again, most recently — must NOT win.
	clock = base.Add(2 * time.Minute)
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true))
	// Established node re-announces to stay fresh.
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))

	got := tr.Current()
	want := bytes.Repeat([]byte{0xaa}, 16)
	if !bytes.Equal(got, want) {
		t.Errorf("Current() = %x, want longest-known node %x", got, want)
	}
}

func TestTrackerAcceptsEightElementAnnounce(t *testing.T) {
	tr := newTestTracker(nil)
	tr.OnAnnounce(pnAnnounce(t, 0xcc, true))
	if got := tr.Current(); !bytes.Equal(got, bytes.Repeat([]byte{0xcc}, 16)) {
		t.Errorf("Current() = %x after 8-element announce, want node cc", got)
	}
}

func TestTrackerDropsStaleNodes(t *testing.T) {
	tr := newTestTracker(nil)
	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	if tr.Current() == nil {
		t.Fatal("fresh node should be selectable")
	}
	// Past the staleness window with no re-announce.
	clock = base.Add(nodeStaleAfter + time.Minute)
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x, want nil for a stale node", got)
	}
}

func TestTrackerRejectsHostileParameters(t *testing.T) {
	// A node announcing parameters we cannot satisfy must be filtered
	// at SELECTION time. Discovering this at send time instead made the
	// error terminal for the MESSAGE (it is neither errNoPropagationNode
	// nor transient), so one hostile announce destroyed all fallback mail.
	for name, appData := range map[string][]byte{
		"stamp cost above local limit": pnAppData(t, true, 256, lxmf.MaxPropagationStampCost+1),
		"absurd stamp cost":            pnAppData(t, true, 256, 200),
		"implausible transfer limit":   pnAppData(t, true, 1, 0),
	} {
		tr := newTestTracker(nil)
		tr.OnAnnounce(&rns.Announce{
			DestHash: bytes.Repeat([]byte{0xee}, 16),
			NameHash: lxmfPropagationNameHash,
			AppData:  appData,
		})
		if got := tr.Current(); got != nil {
			t.Errorf("%s: node selected (%x); want rejected", name, got)
		}
	}
}

func TestTrackerNodeMapIsBounded(t *testing.T) {
	tr := newTestTracker(nil)
	base := time.Unix(1700000000, 0)
	clock := base
	tr.now = func() time.Time { return clock }

	// More distinct announcers than the cap, all fresh.
	for i := 0; i < maxTrackedNodes+100; i++ {
		clock = base.Add(time.Duration(i) * time.Second)
		tr.OnAnnounce(&rns.Announce{
			DestHash: bytes.Repeat([]byte{byte(i % 256), byte(i / 256)}, 8),
			NameHash: lxmfPropagationNameHash,
			AppData:  pnAppData(t, true, 256, 0),
		})
	}
	tr.mu.Lock()
	n := len(tr.nodes)
	tr.mu.Unlock()
	if n > maxTrackedNodes {
		t.Errorf("tracker holds %d nodes, want <= %d", n, maxTrackedNodes)
	}
}

func TestTrackerNodeStateFlipDeselects(t *testing.T) {
	tr := newTestTracker(nil)
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	tr.OnAnnounce(pnAnnounce(t, 0xaa, false))
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x after node flipped to not-accepting, want nil", got)
	}
}

func TestTrackerPinnedNodeWins(t *testing.T) {
	pinned := bytes.Repeat([]byte{0x11}, 16)
	tr := newTestTracker(pinned)

	// Pinned wins even before any announce, and even when a different
	// node has announced more recently.
	if got := tr.Current(); !bytes.Equal(got, pinned) {
		t.Errorf("Current() = %x, want pinned %x (before any announce)", got, pinned)
	}
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	if got := tr.Current(); !bytes.Equal(got, pinned) {
		t.Errorf("Current() = %x, want pinned %x (after other announce)", got, pinned)
	}
}

func TestTrackerIgnoresMalformedAppData(t *testing.T) {
	tr := newTestTracker(nil)
	tr.OnAnnounce(&rns.Announce{
		DestHash: bytes.Repeat([]byte{0xee}, 16),
		NameHash: lxmfPropagationNameHash,
		AppData:  []byte{0x01, 0x02},
	})
	if got := tr.Current(); got != nil {
		t.Errorf("Current() = %x after malformed announce, want nil", got)
	}
}

func TestNormalizePropagationAppDataForSendPropagated(t *testing.T) {
	transport := rns.NewTransport(nil)
	ki := makeKnownIdentity(0xdd, time.Now())
	eightElem, err := msgpack.Marshal([]any{
		false, time.Now().Unix(), true, 256, 256,
		[]any{0, 0, 0}, map[any]any{}, "future-extension",
	})
	if err != nil {
		t.Fatal(err)
	}
	ki.AppData = eightElem
	transport.Restore(ki)

	if _, err := lxmf.ParsePropagationNodeAppData(eightElem); err == nil {
		t.Fatal("expected reticulum-go ParsePropagationNodeAppData to reject 8-element array")
	}

	recalled := transport.Recall(ki.DestHash)
	if recalled == nil {
		t.Fatal("Recall returned nil")
	}
	norm, changed := normalizePropagationAppData(recalled.AppData)
	if !changed {
		t.Fatal("expected 8-element app_data to be normalized")
	}
	recalled.AppData = norm
	transport.Restore(recalled)

	after := transport.Recall(ki.DestHash)
	if after == nil {
		t.Fatal("Recall after Restore returned nil")
	}
	info, err := lxmf.ParsePropagationNodeAppData(after.AppData)
	if err != nil {
		t.Fatalf("ParsePropagationNodeAppData after normalization failed: %v", err)
	}
	if !info.Enabled || info.PerTransferLimitKB != 256 {
		t.Errorf("unexpected parsed info: %+v", info)
	}
}

func TestTrackerSeedRestoresFreshPropagationNodes(t *testing.T) {
	tr := newTestTracker(nil)
	base := time.Unix(1700000000, 0)
	tr.now = func() time.Time { return base }

	fresh := makeKnownIdentity(0xaa, base.Add(-5*time.Minute))
	fresh.NameHash = lxmfPropagationNameHash
	fresh.AppData = pnAppData(t, true, 256, 0)

	stale := makeKnownIdentity(0xbb, base.Add(-nodeStaleAfter-time.Minute))
	stale.NameHash = lxmfPropagationNameHash
	stale.AppData = pnAppData(t, true, 256, 0)

	deliveryPeer := makeKnownIdentity(0xcc, base.Add(-time.Minute))
	deliveryPeer.NameHash = lxmfDeliveryNameHash

	added := tr.Seed([]*rns.KnownIdentity{fresh, stale, deliveryPeer})
	if added != 1 {
		t.Fatalf("Seed added %d entries, want 1", added)
	}
	if got := tr.Current(); !bytes.Equal(got, fresh.DestHash) {
		t.Errorf("Current() = %x, want seeded fresh node %x", got, fresh.DestHash)
	}
}

func TestTrackerOnNodeReadyCallback(t *testing.T) {
	// Auto-discover mode fires on usable node, not unusable.
	tr := newTestTracker(nil)
	calls := 0
	tr.setOnNodeReady(func() { calls++ })

	tr.OnAnnounce(pnAnnounce(t, 0xaa, false))
	if calls != 0 {
		t.Errorf("unusable auto-discovered node fired onNodeReady %d times, want 0", calls)
	}
	tr.OnAnnounce(pnAnnounce(t, 0xbb, true))
	if calls != 1 {
		t.Errorf("usable auto-discovered node fired onNodeReady %d times, want 1", calls)
	}

	// Pinned mode fires when the pinned node announces even if accepting=false
	// or app_data is malformed (public key is still cached for /get).
	pinned := bytes.Repeat([]byte{0x44}, 16)
	trPin := newTestTracker(pinned)
	pinCalls := 0
	trPin.setOnNodeReady(func() { pinCalls++ })

	trPin.OnAnnounce(pnAnnounce(t, 0x55, true)) // unrelated node
	if pinCalls != 0 {
		t.Errorf("non-pinned node fired onNodeReady %d times, want 0", pinCalls)
	}
	trPin.OnAnnounce(pnAnnounce(t, 0x44, false))
	if pinCalls != 1 {
		t.Errorf("pinned node (accepting=false) fired onNodeReady %d times, want 1", pinCalls)
	}
	trPin.OnAnnounce(&rns.Announce{
		DestHash: pinned,
		NameHash: lxmfPropagationNameHash,
		AppData:  []byte{0x01, 0x02},
	})
	if pinCalls != 2 {
		t.Errorf("pinned node (malformed app_data) fired onNodeReady %d times, want 2", pinCalls)
	}
}
