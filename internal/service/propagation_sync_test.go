package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

type fakeRetriever struct {
	mu           sync.Mutex
	deliveryHash []byte
	retrieveFn   func(ctx context.Context, node []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error)
	calls        int
	teardowns    int
	pathReqs     [][]byte
	known        map[string]*rns.KnownIdentity
}

func (f *fakeRetriever) DeliveryHash() []byte { return append([]byte(nil), f.deliveryHash...) }

func (f *fakeRetriever) Retrieve(ctx context.Context, nodeDestHash []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
	f.mu.Lock()
	f.calls++
	fn := f.retrieveFn
	f.mu.Unlock()
	if fn == nil {
		return &lxmf.RetrieveResult{Failed: map[string]error{}}, nil
	}
	return fn(ctx, nodeDestHash, opts)
}

func (f *fakeRetriever) TeardownLinkTo(nodeDestHash []byte) {
	f.mu.Lock()
	f.teardowns++
	f.mu.Unlock()
}

func (f *fakeRetriever) RequestPath(destHash []byte) error {
	f.mu.Lock()
	f.pathReqs = append(f.pathReqs, append([]byte(nil), destHash...))
	f.mu.Unlock()
	return nil
}

func (f *fakeRetriever) RequestPathAfter(destHash []byte, _ time.Duration) error {
	return f.RequestPath(destHash)
}

func (f *fakeRetriever) Recall(destHash []byte) *rns.KnownIdentity {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.known == nil {
		return nil
	}
	return f.known[hex.EncodeToString(destHash)]
}

func (f *fakeRetriever) setKnown(destHash []byte, id *rns.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.known == nil {
		f.known = map[string]*rns.KnownIdentity{}
	}
	f.known[hex.EncodeToString(destHash)] = &rns.KnownIdentity{
		DestHash:  append([]byte(nil), destHash...),
		PublicKey: append([]byte(nil), id.PublicKey()...),
		LastSeen:  time.Now(),
	}
}

func makeSignedLXMF(t *testing.T, senderID *rns.Identity, senderDest, svcDest []byte, content string, stampCost int) (*lxmf.Message, []byte) {
	t.Helper()
	wire, _, err := lxmf.SignAndPackOpportunisticStamped(
		senderID, senderDest, svcDest, nil, []byte(content), nil,
		lxmf.StampOptions{Cost: stampCost},
	)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := lxmf.ParseOpportunisticBody(wire, svcDest)
	if err != nil {
		t.Fatal(err)
	}
	tid := sha256.Sum256(append(append([]byte(nil), svcDest...), wire...))
	return msg, tid[:]
}

func TestSyncOnceDeliversAndPaginates(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)
	senderID, senderDest := newSender(t)

	m1, tid1 := makeSignedLXMF(t, senderID, senderDest, svcDest, "msg-1", 0)
	m2, tid2 := makeSignedLXMF(t, senderID, senderDest, svcDest, "msg-2", 0)
	m3, tid3 := makeSignedLXMF(t, senderID, senderDest, svcDest, "msg-3", 0)

	type stored struct {
		msg *lxmf.Message
		tid []byte
	}
	queue := []stored{{m1, tid1}, {m2, tid2}, {m3, tid3}}

	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		if opts.TransferLimitKB != 512 {
			t.Errorf("TransferLimitKB = %d, want 512", opts.TransferLimitKB)
		}
		if opts.MaxMessages != 2 {
			t.Errorf("MaxMessages = %d, want 2", opts.MaxMessages)
		}
		res := &lxmf.RetrieveResult{Failed: map[string]error{}}
		for _, item := range queue {
			res.Offered = append(res.Offered, item.tid)
		}
		take := opts.MaxMessages
		if take > len(queue) {
			take = len(queue)
		}
		for _, item := range queue[:take] {
			res.Messages = append(res.Messages, &lxmf.RetrievedMessage{
				Message:        item.msg,
				TransientID:    item.tid,
				SenderVerified: true,
			})
			res.Acknowledged = append(res.Acknowledged, item.tid)
		}
		queue = queue[take:]
		return res, nil
	}

	tr := newTestTracker(nodeDest)
	var delivered []string
	syncer := newPropagationSyncer(
		ret, tr, nil,
		func(m *lxmf.Message) { delivered = append(delivered, string(m.Content)) },
		propagationSyncOptions{
			Interval:        5 * time.Minute,
			TransferLimitKB: 512,
			MaxMessages:     2,
			Timeout:         time.Minute,
		},
		logging.Discard(),
	)

	summary := syncer.syncOnce(context.Background())
	if summary.err != nil {
		t.Fatalf("syncOnce error: %v", summary.err)
	}
	if summary.rounds != 2 {
		t.Errorf("rounds = %d, want 2 (batch of 2 + batch of 1)", summary.rounds)
	}
	if len(delivered) != 3 || delivered[0] != "msg-1" || delivered[2] != "msg-3" {
		t.Errorf("delivered = %v, want [msg-1 msg-2 msg-3]", delivered)
	}
}

func TestSyncOnceZeroProgressBreaksLoop(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)
	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		// Node offers 2 messages too large for transfer_limit -> returns 0 bodies.
		return &lxmf.RetrieveResult{
			Offered: [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)},
			Failed:  map[string]error{},
		}, nil
	}
	tr := newTestTracker(nodeDest)
	syncer := newPropagationSyncer(
		ret, tr, nil, nil,
		propagationSyncOptions{Interval: time.Minute, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Minute},
		logging.Discard(),
	)

	summary := syncer.syncOnce(context.Background())
	if summary.rounds != 1 {
		t.Errorf("rounds = %d, want 1 (zero-progress guard must stop looping)", summary.rounds)
	}
}

func TestSyncOncePurgeFailurePreservesMessagesAndUsesHave(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)
	senderID, senderDest := newSender(t)
	m1, tid1 := makeSignedLXMF(t, senderID, senderDest, svcDest, "survive-purge-fail", 0)

	round := 0
	var secondRoundSawHave bool
	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		round++
		if round == 1 {
			// Round 2 succeeded, Round 3 purge errored: non-nil result + err.
			return &lxmf.RetrieveResult{
				Offered: [][]byte{tid1},
				Messages: []*lxmf.RetrievedMessage{{
					Message:        m1,
					TransientID:    tid1,
					SenderVerified: true,
				}},
				Failed: map[string]error{},
			}, errors.New("purge round: /get: request timed out")
		}
		// Next sync: Have(tid1) MUST report true so node purges without re-downloading.
		secondRoundSawHave = opts.Have != nil && opts.Have(tid1)
		return &lxmf.RetrieveResult{
			Offered:      [][]byte{tid1},
			Acknowledged: [][]byte{tid1},
			Failed:       map[string]error{},
		}, nil
	}

	var delivered []string
	syncer := newPropagationSyncer(
		ret, newTestTracker(nodeDest), nil,
		func(m *lxmf.Message) { delivered = append(delivered, string(m.Content)) },
		propagationSyncOptions{Interval: time.Minute, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Minute},
		logging.Discard(),
	)

	s1 := syncer.syncOnce(context.Background())
	if s1.err == nil {
		t.Fatal("first sync should report purge error")
	}
	if len(delivered) != 1 || delivered[0] != "survive-purge-fail" {
		t.Fatalf("delivered after purge error = %v, want message preserved", delivered)
	}

	s2 := syncer.syncOnce(context.Background())
	if s2.err != nil {
		t.Fatalf("second sync error: %v", s2.err)
	}
	if !secondRoundSawHave {
		t.Error("second sync Have(tid1) was false; expected true so node purges without re-download")
	}
	if len(delivered) != 1 {
		t.Errorf("delivered count = %d, want 1 (no duplicate delivery)", len(delivered))
	}
}

func TestSyncOnceSecurityParity(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	otherDest := bytes.Repeat([]byte{0x88}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)

	goodID, goodDest := newSender(t)
	bannedID, bannedDest := newSender(t)

	wrongDestMsg, tidWrong := makeSignedLXMF(t, goodID, goodDest, otherDest, "wrong-dest", 0)
	bannedMsg, tidBanned := makeSignedLXMF(t, bannedID, bannedDest, svcDest, "from-banned", 0)
	unstampedMsg, tidUnstamped := makeSignedLXMF(t, goodID, goodDest, svcDest, "no-stamp", 0)
	stampedMsg, tidStamped := makeSignedLXMF(t, goodID, goodDest, svcDest, "valid-stamp", 4)

	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		return &lxmf.RetrieveResult{
			Offered: [][]byte{tidWrong, tidBanned, tidUnstamped, tidStamped},
			Messages: []*lxmf.RetrievedMessage{
				{Message: wrongDestMsg, TransientID: tidWrong, SenderVerified: true},
				{Message: bannedMsg, TransientID: tidBanned, SenderVerified: true},
				{Message: unstampedMsg, TransientID: tidUnstamped, SenderVerified: true},
				{Message: stampedMsg, TransientID: tidStamped, SenderVerified: true},
			},
			Acknowledged: [][]byte{tidWrong, tidBanned, tidUnstamped, tidStamped},
			Failed:       map[string]error{},
		}, nil
	}

	var delivered []*lxmf.Message
	syncer := newPropagationSyncer(
		ret, newTestTracker(nodeDest),
		func(b []byte) bool { return bytes.Equal(b, bannedDest) },
		func(m *lxmf.Message) { delivered = append(delivered, m) },
		propagationSyncOptions{
			Interval:             time.Minute,
			TransferLimitKB:      512,
			MaxMessages:          32,
			Timeout:              time.Minute,
			InboundStampCost:     4,
			EnforceInboundStamps: true,
		},
		logging.Discard(),
	)

	summary := syncer.syncOnce(context.Background())
	if summary.delivered != 1 || summary.dropped != 3 {
		t.Fatalf("summary delivered=%d dropped=%d, want 1 delivered and 3 dropped", summary.delivered, summary.dropped)
	}
	if len(delivered) != 1 || string(delivered[0].Content) != "valid-stamp" {
		t.Fatalf("delivered = %v, want only valid-stamp", delivered)
	}
	if !delivered[0].StampChecked || !delivered[0].StampValid || delivered[0].StampValue < 4 {
		t.Errorf("stamp fields = checked:%v valid:%v value:%d, want checked+valid+>=4",
			delivered[0].StampChecked, delivered[0].StampValid, delivered[0].StampValue)
	}
}

func TestSyncOnceHoldsUnverifiedSenderUntilAnnounce(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)
	senderID, senderDest := newSender(t)
	badID, _ := newSender(t)

	validMsg, tid1 := makeSignedLXMF(t, senderID, senderDest, svcDest, "wait-for-announce", 0)
	// Forged signature: signed by badID but claiming senderDest.
	forgedMsg, tid2 := makeSignedLXMF(t, badID, senderDest, svcDest, "forged", 0)

	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		return &lxmf.RetrieveResult{
			Offered: [][]byte{tid1, tid2},
			Messages: []*lxmf.RetrievedMessage{
				{Message: validMsg, TransientID: tid1, SenderVerified: false},
				{Message: forgedMsg, TransientID: tid2, SenderVerified: false},
			},
			Acknowledged: [][]byte{tid1, tid2},
			Failed:       map[string]error{},
		}, nil
	}

	deliveredCh := make(chan string, 4)
	syncer := newPropagationSyncer(
		ret, newTestTracker(nodeDest), nil,
		func(m *lxmf.Message) { deliveredCh <- string(m.Content) },
		propagationSyncOptions{Interval: time.Minute, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Minute},
		logging.Discard(),
	)

	summary := syncer.syncOnce(context.Background())
	if summary.held != 2 || summary.delivered != 0 {
		t.Fatalf("summary held=%d delivered=%d, want 2 held / 0 delivered", summary.held, summary.delivered)
	}
	if len(ret.pathReqs) == 0 {
		t.Fatal("expected RequestPathAfter to be issued for unknown sender")
	}

	// Sender announce arrives -> valid message verifies and delivers; forged is dropped.
	ret.setKnown(senderDest, senderID)
	syncer.OnSenderAnnounce(senderDest)

	select {
	case got := <-deliveredCh:
		if got != "wait-for-announce" {
			t.Errorf("delivered %q, want %q", got, "wait-for-announce")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for held message delivery after announce")
	}

	// Ensure forged message did not slip through.
	select {
	case extra := <-deliveredCh:
		t.Fatalf("forged message was delivered: %q", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSyncOnceErrorRecoveryAndBackoff(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)

	var nextErr error
	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		if nextErr != nil {
			return nil, nextErr
		}
		return &lxmf.RetrieveResult{Failed: map[string]error{}}, nil
	}
	syncer := newPropagationSyncer(
		ret, newTestTracker(nodeDest), nil, nil,
		propagationSyncOptions{Interval: 1 * time.Minute, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Minute},
		logging.Discard(),
	)

	// 1. Unknown node -> RequestPath + waitingForNode.
	nextErr = fmt.Errorf("link: %w", rns.ErrLinkPeerUnknown)
	syncer.syncOnce(context.Background())
	if !syncer.waitingForNode.Load() {
		t.Error("waitingForNode should be true after ErrLinkPeerUnknown")
	}
	if len(ret.pathReqs) != 1 || !bytes.Equal(ret.pathReqs[0], nodeDest) {
		t.Errorf("pathReqs = %x, want 1 request for %x", ret.pathReqs, nodeDest)
	}

	// 2. RequestTimeout -> TeardownLinkTo.
	nextErr = fmt.Errorf("/get: %w", rns.ErrRequestTimeout)
	syncer.syncOnce(context.Background())
	if ret.teardowns != 1 {
		t.Errorf("teardowns after ErrRequestTimeout = %d, want 1", ret.teardowns)
	}

	// 3. ErrPropagationNoIdentity -> TeardownLinkTo.
	nextErr = lxmf.ErrPropagationNoIdentity
	syncer.syncOnce(context.Background())
	if ret.teardowns != 2 {
		t.Errorf("teardowns after ErrPropagationNoIdentity = %d, want 2", ret.teardowns)
	}

	// 4. Throttled -> exponential backoff (2m, 4m), then reset on clean sync.
	nextErr = lxmf.ErrPropagationThrottled
	syncer.syncOnce(context.Background())
	if got := syncer.nextInterval(); got != 2*time.Minute {
		t.Errorf("backoff after 1st throttle = %s, want 2m", got)
	}
	syncer.syncOnce(context.Background())
	if got := syncer.nextInterval(); got != 4*time.Minute {
		t.Errorf("backoff after 2nd throttle = %s, want 4m", got)
	}

	// Clean sync resets backoff back to base interval.
	nextErr = nil
	syncer.syncOnce(context.Background())
	if got := syncer.nextInterval(); got != 1*time.Minute {
		t.Errorf("interval after clean sync = %s, want 1m", got)
	}
}

func TestSyncRunPeriodicManualTriggerAndNoDeadlock(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	nodeDest := bytes.Repeat([]byte{0x44}, 16)
	senderID, senderDest := newSender(t)

	var calls atomic.Int32
	var syncer *propagationSyncer
	secondSyncDone := make(chan struct{}, 4)
	reentrantReplyCh := make(chan string, 1)

	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		n := calls.Add(1)
		if n == 1 {
			// Deliver a "/sync" command inside syncOnce to prove calling TriggerSync
			// re-entrantly from deliver() cannot deadlock!
			cmdMsg, tid := makeSignedLXMF(t, senderID, senderDest, svcDest, "/sync", 0)
			return &lxmf.RetrieveResult{
				Offered:      [][]byte{tid},
				Messages:     []*lxmf.RetrievedMessage{{Message: cmdMsg, TransientID: tid, SenderVerified: true}},
				Acknowledged: [][]byte{tid},
				Failed:       map[string]error{},
			}, nil
		}
		select {
		case secondSyncDone <- struct{}{}:
		default:
		}
		return &lxmf.RetrieveResult{Failed: map[string]error{}}, nil
	}

	syncer = newPropagationSyncer(
		ret, newTestTracker(nodeDest), nil,
		func(m *lxmf.Message) {
			if string(m.Content) == "/sync" {
				reentrantReplyCh <- syncer.TriggerSync()
			}
		},
		propagationSyncOptions{Interval: 5 * time.Second, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Second},
		logging.Discard(),
	)
	syncer.startupGrace = 10 * time.Millisecond
	syncer.housekeepInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	// Initial startup sync runs and exercises re-entrant TriggerSync cleanly.
	select {
	case reentrantReply := <-reentrantReplyCh:
		if !strings.Contains(reentrantReply, "already in progress") {
			t.Errorf("re-entrant TriggerSync reply = %q, want 'already in progress'", reentrantReply)
		}
	case <-time.After(time.Second):
		t.Fatal("initial startup sync did not deliver /sync")
	}

	// Wait until the first syncOnce finishes clearing inProgress.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		syncer.stateMu.Lock()
		busy := syncer.inProgress
		syncer.stateMu.Unlock()
		if !busy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Explicit manual trigger wakes the loop immediately without waiting 5s.
	reply := syncer.TriggerSync()
	if !strings.Contains(reply, "Propagation sync triggered") {
		t.Errorf("TriggerSync reply = %q", reply)
	}
	select {
	case <-secondSyncDone:
	case <-time.After(time.Second):
		t.Fatal("manual TriggerSync did not execute")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("syncer.Run did not exit on ctx cancel")
	}
}

func TestSyncRunWakesEarlyOnNodeReadyOnlyWhenWaiting(t *testing.T) {
	svcDest := bytes.Repeat([]byte{0x99}, 16)
	tr := newTestTracker(nil) // auto-discover: starts with no node

	var calls atomic.Int32
	syncedCh := make(chan struct{}, 4)

	ret := &fakeRetriever{deliveryHash: svcDest}
	ret.retrieveFn = func(_ context.Context, _ []byte, _ lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
		calls.Add(1)
		select {
		case syncedCh <- struct{}{}:
		default:
		}
		return &lxmf.RetrieveResult{Failed: map[string]error{}}, nil
	}

	syncer := newPropagationSyncer(
		ret, tr, nil, nil,
		propagationSyncOptions{Interval: 10 * time.Second, TransferLimitKB: 512, MaxMessages: 32, Timeout: time.Second},
		logging.Discard(),
	)
	syncer.startupGrace = 10 * time.Millisecond
	tr.setOnNodeReady(syncer.NotifyNodeReady)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	// Wait for the initial startup sync to observe "no node" and set waitingForNode.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !syncer.waitingForNode.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !syncer.waitingForNode.Load() {
		t.Fatal("expected waitingForNode to be true after startup with no node")
	}

	// First usable propagation node announces -> must wake the loop immediately.
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	select {
	case <-syncedCh:
	case <-time.After(time.Second):
		t.Fatal("syncer did not wake early when first propagation node announced")
	}

	// Subsequent re-announces while healthy must NOT trigger unscheduled extra syncs.
	tr.OnAnnounce(pnAnnounce(t, 0xaa, true))
	select {
	case <-syncedCh:
		t.Fatal("re-announce of healthy node should not trigger extra unscheduled sync")
	case <-time.After(80 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("retrieve calls = %d, want 1", got)
	}

	cancel()
	<-done
}

// --- Full in-process wire-level E2E test against a real /get propagation node ---

type memInterface struct {
	peer   *memInterface
	inbox  chan []byte
	done   chan struct{}
	closed atomic.Bool
}

func newPairedMemInterfaces() (*memInterface, *memInterface, func()) {
	a := &memInterface{inbox: make(chan []byte, 256), done: make(chan struct{})}
	b := &memInterface{inbox: make(chan []byte, 256), done: make(chan struct{})}
	a.peer = b
	b.peer = a
	var once sync.Once
	stop := func() {
		once.Do(func() {
			a.closed.Store(true)
			b.closed.Store(true)
			close(a.done)
			close(b.done)
		})
	}
	return a, b, stop
}

func (m *memInterface) Send(packet []byte) error {
	if m.closed.Load() || m.peer.closed.Load() {
		return errors.New("closed")
	}
	cp := append([]byte(nil), packet...)
	select {
	case m.peer.inbox <- cp:
		return nil
	case <-m.peer.done:
		return errors.New("closed")
	}
}

func (m *memInterface) Inbox() <-chan []byte  { return m.inbox }
func (m *memInterface) Done() <-chan struct{} { return m.done }

type inProcessPropNode struct {
	mu    sync.Mutex
	store map[string][]byte // hex(transient_id) -> propagated body (without prop stamp)
}

func (n *inProcessPropNode) handleGet(rc *rns.RequestContext) (any, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if rc.RemoteIdentity == nil {
		return 0xf0, nil // ERROR_NO_IDENTITY
	}
	data, ok := rc.Data.([]any)
	if !ok || len(data) < 2 {
		return 0xf4, nil
	}
	wants, haves := data[0], data[1]
	if wants == nil && haves == nil {
		ids := make([]any, 0, len(n.store))
		for _, body := range n.store {
			tid := sha256.Sum256(body)
			ids = append(ids, tid[:])
		}
		return ids, nil
	}
	if hl, ok := haves.([]any); ok {
		for _, h := range hl {
			if b, ok := h.([]byte); ok {
				delete(n.store, hex.EncodeToString(b))
			}
		}
	}
	out := []any{}
	if wl, ok := wants.([]any); ok {
		for _, w := range wl {
			if b, ok := w.([]byte); ok {
				if body, found := n.store[hex.EncodeToString(b)]; found {
					out = append(out, body)
				}
			}
		}
	}
	return out, nil
}

func (n *inProcessPropNode) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.store)
}

func TestPropagationSyncEndToEndViaRealGet(t *testing.T) {
	nodeID, err := rns.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodeDest := nodeID.DestinationHashFor(lxmf.PropagationFullName())
	nodeHex := hex.EncodeToString(nodeDest)

	dir := t.TempDir()
	cfgSrc := fmt.Sprintf(`[service]
display_name = "prop-e2e"
identity_path = %q
state_path = %q
history_path = %q

[propagation]
enabled = true
mode = "receive_only"
node = %q
sync_interval = "10s"
`, filepath.Join(dir, "id"), filepath.Join(dir, "state.json"), filepath.Join(dir, "history.json"), nodeHex)
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if svc.instanceUnlock != nil {
			svc.instanceUnlock()
		}
	})

	// Set up Alice (member, known), Bob (member, forward target), and Carol (member, unknown until announce).
	aliceID, aliceDest := newSender(t)
	bobDest := bytes.Repeat([]byte{0xBB}, 16)
	carolID, carolDest := newSender(t)

	for _, member := range [][]byte{aliceDest, bobDest, carolDest} {
		if _, err := svc.roster.AddOrUpdate(member, svc.now()); err != nil {
			t.Fatal(err)
		}
	}
	_ = svc.roster.SetNickname(hex.EncodeToString(aliceDest), "Alice")
	_ = svc.roster.SetNickname(hex.EncodeToString(carolDest), "Carol")

	// Pair svc.transport with a real peer transport hosting the propagation node.
	svcIface, nodeIface, stopWire := newPairedMemInterfaces()
	svc.transport.AddInterface(svcIface)

	nodeTransport := rns.NewTransport(nil)
	nodeTransport.AddInterface(nodeIface)

	propNode := &inProcessPropNode{store: map[string][]byte{}}
	if err := nodeTransport.RegisterRequestHandler(lxmf.MessageGetPath, rns.AllowAll, nil, propNode.handleGet); err != nil {
		t.Fatal(err)
	}
	if err := nodeTransport.RegisterLocal(&rns.LocalDestination{
		DestHash: nodeDest,
		Identity: nodeID,
		OnPacket: func(*rns.Packet) {},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go svc.transport.Run(ctx)
	go nodeTransport.Run(ctx)
	t.Cleanup(func() { cancel(); stopWire() })

	// Announce the propagation node and Alice (NOT Carol yet).
	pnAnn, err := rns.BuildAnnounce(nodeID, lxmf.PropagationFullName(), pnAppData(t, true, 256, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeTransport.Broadcast(pnAnn); err != nil {
		t.Fatal(err)
	}
	aliceAppData, _ := rns.EncodeLXMFAppData([]byte("Alice"), nil)
	aliceAnn, err := rns.BuildAnnounce(aliceID, lxmf.FullName(), aliceAppData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeTransport.Broadcast(aliceAnn); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.transport.Recall(nodeDest) != nil && svc.transport.Recall(aliceDest) != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if svc.transport.Recall(nodeDest) == nil || svc.transport.Recall(aliceDest) == nil {
		t.Fatal("announces for propagation node and Alice never arrived")
	}

	// Store propagated messages from Alice (known) and Carol (unknown) on the node.
	svcDest := svc.delivery.Hash()
	svcIDHash := sha256.Sum256(svc.identity.PublicKey())
	aliceBody, aliceTID, _, err := lxmf.SignAndPackPropagated(
		aliceID, aliceDest, svcDest,
		svc.identity.X25519Public(), svcIDHash[:rns.IdentityHashLen],
		nil, []byte("hello via prop node"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	carolBody, carolTID, _, err := lxmf.SignAndPackPropagated(
		carolID, carolDest, svcDest,
		svc.identity.X25519Public(), svcIDHash[:rns.IdentityHashLen],
		nil, []byte("hello from unannounced carol"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	propNode.mu.Lock()
	propNode.store[hex.EncodeToString(aliceTID)] = aliceBody
	propNode.store[hex.EncodeToString(carolTID)] = carolBody
	propNode.mu.Unlock()

	// Run a real 3-round /get sync over the Reticulum Link!
	summary := svc.propSync.syncOnce(ctx)
	if summary.err != nil {
		t.Fatalf("real /get syncOnce failed: %v", summary.err)
	}
	if summary.delivered != 1 || summary.held != 1 {
		t.Fatalf("summary delivered=%d held=%d, want 1 delivered (Alice) and 1 held (Carol)", summary.delivered, summary.held)
	}
	if remaining := propNode.count(); remaining != 0 {
		t.Errorf("propagation node still holds %d messages after Round 3 purge, want 0", remaining)
	}

	// Alice's message was fanned out to Bob and recorded in history.
	bobMsgs := queuedTo(svc.outbound, bobDest)
	if len(bobMsgs) != 1 || bobMsgs[0] != "[Alice] hello via prop node" {
		t.Fatalf("Bob outbound queue = %v, want ['[Alice] hello via prop node']", bobMsgs)
	}
	if got := svc.history.Len(); got != 1 {
		t.Fatalf("history len = %d, want 1", got)
	}

	// Now Carol's announce arrives -> her held propagated message verifies and fans out to Bob!
	carolAppData, _ := rns.EncodeLXMFAppData([]byte("Carol"), nil)
	carolAnn, err := rns.BuildAnnounce(carolID, lxmf.FullName(), carolAppData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeTransport.Broadcast(carolAnn); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.history.Len() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if svc.history.Len() != 2 {
		t.Fatalf("Carol's held message never delivered after her announce (history len = %d)", svc.history.Len())
	}
	bobMsgs = queuedTo(svc.outbound, bobDest)
	if len(bobMsgs) != 2 || bobMsgs[1] != "[Carol] hello from unannounced carol" {
		t.Fatalf("Bob outbound queue after Carol announce = %v", bobMsgs)
	}

	// Verify receive_only mode kept outbound propagation disabled on OutboundQueue.
	svc.outbound.mu.Lock()
	propFallback, propAlways := svc.outbound.propagationFallback, svc.outbound.propagationAlways
	svc.outbound.mu.Unlock()
	if propFallback || propAlways {
		t.Errorf("receive_only mode enabled outbound propagation (fallback=%v always=%v)", propFallback, propAlways)
	}
}
