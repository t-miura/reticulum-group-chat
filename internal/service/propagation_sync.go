package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thatSFguy/reticulum-go/lxmf"
	"github.com/thatSFguy/reticulum-go/rns"
	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

const (
	// defaultSyncStartupGrace gives freshly dialed TCP interfaces and
	// startup path requests a moment to settle before the first /get poll.
	defaultSyncStartupGrace = 5 * time.Second

	// defaultLinkSettleDelay is paused once after AcquireLink establishes
	// a brand-new link to a propagation node so Transport.handleLRProof's
	// LRRTT + LINKIDENTIFY packets flush onto the wire ahead of /get.
	defaultLinkSettleDelay = 50 * time.Millisecond

	// maxSyncRoundsPerTick bounds pagination within a single sync cycle so
	// a large backlog drains in chunks without starving timers or locking
	// the sync loop indefinitely.
	maxSyncRoundsPerTick = 8

	// maxSyncBackoffFloor is the minimum ceiling for exponential backoff
	// after propagation throttling (0xf6) or access denial (0xf1).
	maxSyncBackoffFloor = 30 * time.Minute

	// seenTransientTTL / seenTransientMax bound the transient_id cache used
	// by RetrieveOptions.Have to avoid re-downloading messages whose Round 3
	// purge failed or that a node re-offers.
	seenTransientTTL = 24 * time.Hour
	seenTransientMax = 8192

	// Unverified retrieved-message hold limits. RetrievePropagated purges a
	// parsed message from the node in Round 3 even when SenderVerified is
	// false (sender not in Transport.known yet), so we hold it briefly while
	// requesting the sender's path rather than either dropping it or
	// trusting an unverified signature.
	retrievedHoldTTL          = 60 * time.Second
	retrievedHoldMaxTotal     = 64
	retrievedHoldMaxPerSender = 4
	retrievedHoldMaxBytes     = 2 << 20 // 2 MiB
	retrievedHoldPathRetry    = 20 * time.Second
	heldHousekeepInterval     = 10 * time.Second

	// Per-sender stamp failure budget for retrieved messages, matching
	// reticulum-go's lxmf/stamp_budget.go (4 failures burst, 1 refill/30s)
	// so a propagation backlog of unstamped messages cannot trigger
	// unbounded 768 KiB workblock allocations.
	retrievedStampFailureBurst  = 4
	retrievedStampFailureRefill = 30 * time.Second
	retrievedStampBudgetMax     = 4096
)

// propagationRetriever is the subset of *lxmf.Delivery + *rns.Transport
// that propagationSyncer calls into. Defined as an interface so unit tests
// can inject fakes without standing up real sockets.
type propagationRetriever interface {
	DeliveryHash() []byte
	Retrieve(ctx context.Context, nodeDestHash []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error)
	TeardownLinkTo(nodeDestHash []byte)
	RequestPath(destHash []byte) error
	RequestPathAfter(destHash []byte, minInterval time.Duration) error
	Recall(destHash []byte) *rns.KnownIdentity
}

type deliveryRetriever struct {
	delivery        *lxmf.Delivery
	transport       *rns.Transport
	linkSettleDelay time.Duration
}

func newDeliveryRetriever(delivery *lxmf.Delivery, transport *rns.Transport) *deliveryRetriever {
	return &deliveryRetriever{
		delivery:        delivery,
		transport:       transport,
		linkSettleDelay: defaultLinkSettleDelay,
	}
}

func (d *deliveryRetriever) DeliveryHash() []byte {
	return d.delivery.Hash()
}

func (d *deliveryRetriever) Retrieve(ctx context.Context, nodeDestHash []byte, opts lxmf.RetrieveOptions) (*lxmf.RetrieveResult, error) {
	// If no active link exists yet, open one first and give handleLRProof a
	// brief moment to emit LRRTT + LINKIDENTIFY before RetrievePropagated
	// sends /get — prevents the responder seeing /get before LRRTT transitions
	// the link from HANDSHAKE to ACTIVE.
	if d.transport.LinkManager().ActiveTo(nodeDestHash) == nil {
		timeout := d.delivery.PropagationSendTimeout
		if timeout <= 0 {
			timeout = lxmf.DefaultPropagationSendTimeout
		}
		if _, err := d.transport.AcquireLink(nodeDestHash, timeout); err != nil {
			return nil, fmt.Errorf("link to propagation node %x: %w", safePrefix(nodeDestHash), err)
		}
		if d.linkSettleDelay > 0 {
			timer := time.NewTimer(d.linkSettleDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.delivery.RetrievePropagated(nodeDestHash, opts)
}

func (d *deliveryRetriever) TeardownLinkTo(nodeDestHash []byte) {
	if l := d.transport.LinkManager().ActiveTo(nodeDestHash); l != nil {
		d.transport.TeardownLink(l.ID)
	}
}

func (d *deliveryRetriever) RequestPath(destHash []byte) error {
	return d.transport.RequestPath(destHash)
}

func (d *deliveryRetriever) RequestPathAfter(destHash []byte, minInterval time.Duration) error {
	return d.transport.RequestPathAfter(destHash, minInterval)
}

func (d *deliveryRetriever) Recall(destHash []byte) *rns.KnownIdentity {
	return d.transport.Recall(destHash)
}

type propagationSyncOptions struct {
	Interval        time.Duration
	TransferLimitKB int
	MaxMessages     int
	Timeout         time.Duration

	InboundStampCost     int
	EnforceInboundStamps bool
}

// propagationSyncer periodically polls the selected LXMF propagation node
// via SPEC §5.8.3 /get, validates retrieved messages (DestHash, banlist,
// signature verification / unknown-sender hold, inbound stamps), and hands
// verified messages into Service.onLXMFReceived.
type propagationSyncer struct {
	retriever propagationRetriever
	nodes     *propagationTracker
	isBanned  func(senderBytes []byte) bool
	deliver   func(*lxmf.Message)
	logger    *logging.Logger
	now       func() time.Time

	interval             time.Duration
	transferLimitKB      int
	maxMessages          int
	timeout              time.Duration
	inboundStampCost     int
	enforceInboundStamps bool

	// Tunables for deterministic testing.
	startupGrace      time.Duration
	maxRounds         int
	housekeepInterval time.Duration

	seen        *transientIDCache
	hold        *retrievedHoldBuffer
	stampBudget *retrievedStampBudget

	manualTriggerCh chan struct{}
	nodeReadyCh     chan struct{}
	waitingForNode  atomic.Bool
	loggedNoNode    atomic.Bool

	stateMu       sync.Mutex
	inProgress    bool
	lastSyncAt    time.Time
	lastSuccessAt time.Time
	lastNodeHex   string
	lastError     string
	lastFetched   int
	totalFetched  int
	backoff       time.Duration
}

func newPropagationSyncer(
	retriever propagationRetriever,
	nodes *propagationTracker,
	isBanned func([]byte) bool,
	deliver func(*lxmf.Message),
	opts propagationSyncOptions,
	logger *logging.Logger,
) *propagationSyncer {
	if logger == nil {
		logger = logging.Discard()
	}
	s := &propagationSyncer{
		retriever:            retriever,
		nodes:                nodes,
		isBanned:             isBanned,
		deliver:              deliver,
		logger:               logger,
		now:                  time.Now,
		interval:             opts.Interval,
		transferLimitKB:      opts.TransferLimitKB,
		maxMessages:          opts.MaxMessages,
		timeout:              opts.Timeout,
		inboundStampCost:     opts.InboundStampCost,
		enforceInboundStamps: opts.EnforceInboundStamps,
		startupGrace:         defaultSyncStartupGrace,
		maxRounds:            maxSyncRoundsPerTick,
		housekeepInterval:    heldHousekeepInterval,
		seen:                 newTransientIDCache(seenTransientTTL, seenTransientMax),
		hold:                 newRetrievedHoldBuffer(retrievedHoldTTL, retrievedHoldPathRetry),
		stampBudget:          newRetrievedStampBudget(),
		manualTriggerCh:      make(chan struct{}, 1),
		nodeReadyCh:          make(chan struct{}, 1),
	}
	return s
}

// NotifyNodeReady wakes the sync loop early when it previously had no
// reachable propagation node. Re-announces of an already-working node are
// ignored so steady-state sync cadence stays governed by sync_interval.
func (s *propagationSyncer) NotifyNodeReady() {
	if !s.waitingForNode.Load() {
		return
	}
	select {
	case s.nodeReadyCh <- struct{}{}:
	default:
	}
}

// TriggerSync requests an immediate propagation sync cycle without blocking.
// Safe to invoke from /sync even if the /sync command itself arrived via a
// propagation node.
func (s *propagationSyncer) TriggerSync() string {
	node := s.nodes.Current()
	if node == nil {
		return "No propagation node known yet; sync will run automatically once one announces."
	}
	nodePrefix := hex.EncodeToString(safePrefix(node))

	s.stateMu.Lock()
	inProgress := s.inProgress
	lastSyncAt := s.lastSyncAt
	totalFetched := s.totalFetched
	lastErr := s.lastError
	s.stateMu.Unlock()

	if inProgress {
		return fmt.Sprintf("Propagation sync already in progress (node %s).", nodePrefix)
	}

	select {
	case s.manualTriggerCh <- struct{}{}:
	default:
	}

	msg := fmt.Sprintf("Propagation sync triggered (node %s).", nodePrefix)
	if !lastSyncAt.IsZero() {
		age := s.now().Sub(lastSyncAt).Round(time.Second)
		if age < 0 {
			age = 0
		}
		msg += fmt.Sprintf("\nLast sync: %s ago (total fetched: %d", age, totalFetched)
		if lastErr != "" {
			msg += ", last error: " + lastErr
		}
		msg += ")."
	}
	return msg
}

// Run drives periodic propagation-node retrieval until ctx is cancelled.
func (s *propagationSyncer) Run(ctx context.Context) {
	initialDelay := s.startupGrace
	if s.interval > 0 && initialDelay > s.interval {
		initialDelay = s.interval
	}
	if initialDelay < 0 {
		initialDelay = 0
	}

	syncTimer := time.NewTimer(initialDelay)
	defer syncTimer.Stop()

	housekeepTicker := time.NewTicker(s.housekeepInterval)
	defer housekeepTicker.Stop()

	resetTimer := func(d time.Duration) {
		if !syncTimer.Stop() {
			select {
			case <-syncTimer.C:
			default:
			}
		}
		syncTimer.Reset(d)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-housekeepTicker.C:
			s.housekeepHeld()
		case <-syncTimer.C:
			s.syncOnce(ctx)
			resetTimer(s.nextInterval())
		case <-s.nodeReadyCh:
			s.syncOnce(ctx)
			resetTimer(s.nextInterval())
		case <-s.manualTriggerCh:
			s.syncOnce(ctx)
			resetTimer(s.nextInterval())
		}
	}
}

func (s *propagationSyncer) nextInterval() time.Duration {
	s.stateMu.Lock()
	bo := s.backoff
	s.stateMu.Unlock()
	if bo > s.interval {
		return bo
	}
	return s.interval
}

func (s *propagationSyncer) bumpBackoff() time.Duration {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	maxCap := maxSyncBackoffFloor
	if fourX := 4 * s.interval; fourX > maxCap {
		maxCap = fourX
	}
	next := s.backoff * 2
	if next < 2*s.interval {
		next = 2 * s.interval
	}
	if next <= 0 {
		next = time.Minute
	}
	if next > maxCap {
		next = maxCap
	}
	s.backoff = next
	return next
}

func (s *propagationSyncer) resetBackoff() {
	s.stateMu.Lock()
	s.backoff = 0
	s.stateMu.Unlock()
}

type syncCycleSummary struct {
	nodeHex      string
	rounds       int
	offered      int
	fetched      int
	delivered    int
	held         int
	dropped      int
	failed       int
	acknowledged int
	err          error
}

// syncOnce executes one serialized retrieval cycle (up to maxRounds
// pagination steps) against the currently selected propagation node.
func (s *propagationSyncer) syncOnce(ctx context.Context) syncCycleSummary {
	node := s.nodes.Current()
	if node == nil {
		s.waitingForNode.Store(true)
		if s.loggedNoNode.CompareAndSwap(false, true) {
			s.logger.Infof("propagation sync: waiting for a usable propagation node announce")
		} else {
			s.logger.Debugf("propagation sync: no usable propagation node available yet")
		}
		return syncCycleSummary{}
	}
	s.loggedNoNode.Store(false)

	nodeHex := hex.EncodeToString(node)
	nodeShort := nodeHex[:8]

	s.stateMu.Lock()
	s.inProgress = true
	s.stateMu.Unlock()

	var summary syncCycleSummary
	summary.nodeHex = nodeHex

	defer func() {
		now := s.now()
		s.stateMu.Lock()
		s.inProgress = false
		s.lastSyncAt = now
		s.lastNodeHex = nodeHex
		s.lastFetched = summary.fetched
		s.totalFetched += summary.fetched
		if summary.err != nil {
			s.lastError = summary.err.Error()
		} else {
			s.lastError = ""
			s.lastSuccessAt = now
		}
		s.stateMu.Unlock()
	}()

	maxRounds := s.maxRounds
	if maxRounds <= 0 {
		maxRounds = maxSyncRoundsPerTick
	}

	for round := 0; round < maxRounds; round++ {
		if err := ctx.Err(); err != nil {
			summary.err = err
			return summary
		}
		summary.rounds++

		opts := lxmf.RetrieveOptions{
			Have: func(tid []byte) bool {
				return s.seen.has(tid, s.now())
			},
			MaxMessages:     s.maxMessages,
			TransferLimitKB: s.transferLimitKB,
			Timeout:         s.timeout,
		}

		res, err := s.retriever.Retrieve(ctx, node, opts)

		roundFetched := 0
		roundAcked := 0
		roundOffered := 0
		roundFailed := 0

		// Always process downloaded messages BEFORE inspecting err:
		// RetrievePropagated returns a non-nil result alongside an error
		// when Round 2 succeeded and Round 3 purge failed. Recording their
		// TransientIDs ensures the next sync purges them via `Have` without
		// re-downloading or losing them.
		if res != nil {
			s.waitingForNode.Store(false)
			roundOffered = len(res.Offered)
			roundAcked = len(res.Acknowledged)
			roundFailed = len(res.Failed)
			summary.offered += roundOffered
			summary.acknowledged += roundAcked
			summary.failed += roundFailed

			for tidHex, ferr := range res.Failed {
				prefix := tidHex
				if len(prefix) > 8 {
					prefix = prefix[:8]
				}
				s.logger.Warnf("propagation sync: node %s failed to parse/verify message %s: %v",
					nodeShort, prefix, ferr)
			}

			now := s.now()
			for _, rm := range res.Messages {
				if rm == nil || rm.Message == nil {
					continue
				}
				if len(rm.TransientID) > 0 {
					s.seen.record(rm.TransientID, now)
				}
				roundFetched++
				summary.fetched++
				switch s.handleRetrieved(rm) {
				case retrievedDelivered:
					summary.delivered++
				case retrievedHeld:
					summary.held++
				default:
					summary.dropped++
				}
			}
		}

		if err != nil {
			summary.err = err
			switch {
			case errors.Is(err, rns.ErrLinkPeerUnknown):
				s.waitingForNode.Store(true)
				if rerr := s.retriever.RequestPath(node); rerr != nil {
					s.logger.Warnf("propagation sync: node %s unknown and path request failed: %v", nodeShort, rerr)
				} else {
					s.logger.Infof("propagation sync: node %s unknown — requested path", nodeShort)
				}
			case errors.Is(err, lxmf.ErrPropagationThrottled):
				bo := s.bumpBackoff()
				s.logger.Warnf("propagation sync: node %s throttled request (0xf6) — backing off for %s", nodeShort, bo)
			case errors.Is(err, lxmf.ErrPropagationNoAccess):
				bo := s.bumpBackoff()
				s.logger.Warnf("propagation sync: node %s denied access (0xf1) — backing off for %s", nodeShort, bo)
			case errors.Is(err, rns.ErrRequestTimeout) || errors.Is(err, lxmf.ErrPropagationNoIdentity):
				s.retriever.TeardownLinkTo(node)
				s.logger.Warnf("propagation sync: node %s failed (%v) — closed link for fresh reconnect", nodeShort, err)
			case roundFetched > 0:
				s.logger.Warnf("propagation sync: node %s purge round failed after delivering %d message(s) (will re-ack next sync): %v",
					nodeShort, roundFetched, err)
			default:
				s.logger.Warnf("propagation sync: node %s failed: %v", nodeShort, err)
			}
			return summary
		}

		// Clean round succeeded.
		s.waitingForNode.Store(false)
		s.resetBackoff()

		if roundOffered == 0 || roundOffered-roundAcked <= 0 {
			break
		}
		if roundFetched == 0 && roundAcked == 0 {
			s.logger.Warnf("propagation sync: node %s offered %d message(s) but returned 0 within %dKB limit (failed=%d) — stopping cycle",
				nodeShort, roundOffered, s.transferLimitKB, roundFailed)
			break
		}
	}

	if summary.fetched > 0 || summary.held > 0 || summary.acknowledged > 0 {
		s.logger.Infof("propagation sync: node %s complete (rounds=%d fetched=%d delivered=%d held=%d dropped=%d acked=%d failed=%d)",
			nodeShort, summary.rounds, summary.fetched, summary.delivered, summary.held, summary.dropped, summary.acknowledged, summary.failed)
	} else {
		s.logger.Debugf("propagation sync: node %s complete — no waiting messages", nodeShort)
	}
	return summary
}

type retrievedDisposition int

const (
	retrievedDropped retrievedDisposition = iota
	retrievedDelivered
	retrievedHeld
)

// handleRetrieved enforces full inbound security parity (DestHash match,
// banlist, Ed25519 signature verification or bounded unknown-sender hold,
// and inbound stamp validation) before handing a message to onLXMFReceived.
func (s *propagationSyncer) handleRetrieved(rm *lxmf.RetrievedMessage) retrievedDisposition {
	msg := rm.Message
	if myDest := s.retriever.DeliveryHash(); len(myDest) > 0 && !bytes.Equal(msg.DestHash, myDest) {
		s.logger.Warnf("propagation sync: dropping message addressed to %x, not us (%x)",
			safePrefix(msg.DestHash), safePrefix(myDest))
		return retrievedDropped
	}
	if s.isBanned != nil && s.isBanned(msg.SourceHash) {
		s.logger.Infof("propagation sync: dropping banned sender %x", safePrefix(msg.SourceHash))
		return retrievedDropped
	}

	if !rm.SenderVerified {
		return s.holdUnverified(msg)
	}

	if !s.validateRetrievedStamp(msg) {
		return retrievedDropped
	}
	if s.deliver != nil {
		s.deliver(msg)
	}
	return retrievedDelivered
}

func (s *propagationSyncer) holdUnverified(msg *lxmf.Message) retrievedDisposition {
	now := s.now()
	s.hold.expire(now)
	res := s.hold.add(msg, estimateMessageBytes(msg), now)
	switch res {
	case holdBufFull:
		s.logger.Warnf("propagation sync: sender %x unknown — hold buffer full, dropping message", safePrefix(msg.SourceHash))
		return retrievedDropped
	case holdBufDuplicate:
		s.logger.Debugf("propagation sync: sender %x unknown — duplicate already held", safePrefix(msg.SourceHash))
	case holdBufAdded:
		s.logger.Infof("propagation sync: sender %x unknown — holding retrieved message for its announce", safePrefix(msg.SourceHash))
	}

	if err := s.retriever.RequestPathAfter(msg.SourceHash, retrievedHoldPathRetry); err != nil {
		s.logger.Warnf("propagation sync: path? for unknown sender %x: %v", safePrefix(msg.SourceHash), err)
	}

	// Close the race where the sender's announce arrived between
	// parseRetrieved's Recall and hold.add above.
	if known := s.retriever.Recall(msg.SourceHash); known != nil {
		s.releaseHeld(msg.SourceHash, known)
	}
	return retrievedHeld
}

// OnSenderAnnounce releases any held unverified retrieved messages from
// senderDestHash once a verified lxmf.delivery announce has populated
// Transport.known. Called from the Transport dispatcher goroutine, so all
// verification / stamp work runs off-dispatcher on a single serial worker.
func (s *propagationSyncer) OnSenderAnnounce(senderDestHash []byte) {
	if s == nil || len(senderDestHash) != rns.IdentityHashLen {
		return
	}
	if !s.hold.hasSender(senderDestHash) {
		return
	}
	known := s.retriever.Recall(senderDestHash)
	if known == nil {
		return
	}
	s.releaseHeld(senderDestHash, known)
}

func (s *propagationSyncer) releaseHeld(senderDestHash []byte, known *rns.KnownIdentity) {
	if s.hold.release(senderDestHash, known) {
		go s.drainHeldReady()
	}
}

func (s *propagationSyncer) drainHeldReady() {
	for {
		item, ok := s.hold.nextReady()
		if !ok {
			return
		}
		if s.isBanned != nil && s.isBanned(item.msg.SourceHash) {
			s.logger.Infof("propagation sync: dropping held message from banned sender %x", safePrefix(item.msg.SourceHash))
			continue
		}
		if err := item.msg.Verify(item.known.Ed25519Public()); err != nil {
			s.logger.Warnf("propagation sync: held message from %x failed signature verification: %v",
				safePrefix(item.msg.SourceHash), err)
			continue
		}
		if !s.validateRetrievedStamp(item.msg) {
			continue
		}
		if s.deliver != nil {
			s.deliver(item.msg)
		}
	}
}

func (s *propagationSyncer) housekeepHeld() {
	now := s.now()
	for _, expired := range s.hold.expire(now) {
		s.logger.Infof("propagation sync: sender %x never announced — held retrieved message expired",
			safePrefix(expired.msg.SourceHash))
	}
	for _, sender := range s.hold.sendersDueForPathRetry(now) {
		if err := s.retriever.RequestPathAfter(sender, retrievedHoldPathRetry); err != nil {
			s.logger.Debugf("propagation sync: path? retry for held sender %x: %v", safePrefix(sender), err)
		}
	}
}

// validateRetrievedStamp enforces service.inbound_stamp_cost and
// service.enforce_inbound_stamps on propagation-retrieved messages, matching
// lxmf.Delivery.checkInboundStamp so propagation cannot bypass stamp policy.
func (s *propagationSyncer) validateRetrievedStamp(msg *lxmf.Message) bool {
	cost := s.inboundStampCost
	if cost <= 0 {
		return true
	}
	now := s.now()
	if !s.stampBudget.allow(msg.SourceHash, now) {
		msg.StampChecked = false
		msg.StampValid = false
		if s.enforceInboundStamps {
			s.logger.Infof("propagation sync: dropping message from %x — stamp failure budget exhausted",
				safePrefix(msg.SourceHash))
			return false
		}
		s.logger.Infof("propagation sync: skipping stamp validation for %x — failure budget exhausted",
			safePrefix(msg.SourceHash))
		return true
	}

	val, err := msg.ValidateStamp(cost)
	msg.StampChecked = true
	msg.StampValue = val
	msg.StampValid = err == nil
	if err != nil {
		s.stampBudget.charge(msg.SourceHash, now)
		if s.enforceInboundStamps {
			s.logger.Infof("propagation sync: dropping message from %x: %v", safePrefix(msg.SourceHash), err)
			return false
		}
		s.logger.Infof("propagation sync: accepting unstamped/underpaid message from %x: %v", safePrefix(msg.SourceHash), err)
	}
	return true
}

func estimateMessageBytes(msg *lxmf.Message) int {
	size := len(msg.Title) + len(msg.Content) + 256
	for _, v := range msg.Fields {
		if b, ok := v.([]byte); ok {
			size += len(b)
		} else if list, ok := v.([]any); ok {
			for _, elem := range list {
				if b, ok := elem.([]byte); ok {
					size += len(b)
				}
			}
		}
	}
	return size
}

// transientIDCache remembers recently retrieved 32-byte transient_ids for
// RetrieveOptions.Have so messages whose Round 3 purge failed are purged on
// the next sync without being re-downloaded.
type transientIDCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newTransientIDCache(ttl time.Duration, max int) *transientIDCache {
	return &transientIDCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
		max:  max,
	}
}

func (c *transientIDCache) has(tid []byte, now time.Time) bool {
	if c == nil || len(tid) == 0 || c.ttl <= 0 {
		return false
	}
	key := hex.EncodeToString(tid)
	c.mu.Lock()
	defer c.mu.Unlock()
	ts, ok := c.seen[key]
	if !ok {
		return false
	}
	if now.Sub(ts) >= c.ttl {
		delete(c.seen, key)
		return false
	}
	return true
}

func (c *transientIDCache) record(tid []byte, now time.Time) {
	if c == nil || len(tid) == 0 || c.ttl <= 0 {
		return
	}
	key := hex.EncodeToString(tid)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[key] = now
	if len(c.seen) <= c.max {
		return
	}
	for k, ts := range c.seen {
		if now.Sub(ts) >= c.ttl {
			delete(c.seen, k)
		}
	}
	for len(c.seen) > c.max {
		var oldestKey string
		var oldestAt time.Time
		for k, ts := range c.seen {
			if oldestKey == "" || ts.Before(oldestAt) {
				oldestKey, oldestAt = k, ts
			}
		}
		if oldestKey == "" {
			return
		}
		delete(c.seen, oldestKey)
	}
}

type holdBufResult int

const (
	holdBufAdded holdBufResult = iota
	holdBufDuplicate
	holdBufFull
)

type heldRetrieved struct {
	msg         *lxmf.Message
	size        int
	heldAt      time.Time
	lastPathReq time.Time
	known       *rns.KnownIdentity
}

type retrievedHoldBuffer struct {
	mu       sync.Mutex
	bySender map[string][]heldRetrieved
	ready    []heldRetrieved
	draining bool
	count    int
	bytes    int
	ttl      time.Duration
	retry    time.Duration
}

func newRetrievedHoldBuffer(ttl, retry time.Duration) *retrievedHoldBuffer {
	return &retrievedHoldBuffer{
		bySender: make(map[string][]heldRetrieved),
		ttl:      ttl,
		retry:    retry,
	}
}

func (h *retrievedHoldBuffer) add(msg *lxmf.Message, size int, now time.Time) holdBufResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(msg.SourceHash)
	queue := h.bySender[key]
	dedup := msg.DedupKey()
	for _, existing := range queue {
		if len(dedup) > 0 && bytes.Equal(existing.msg.DedupKey(), dedup) {
			return holdBufDuplicate
		}
	}
	if len(queue) >= retrievedHoldMaxPerSender ||
		h.count >= retrievedHoldMaxTotal ||
		h.bytes+size > retrievedHoldMaxBytes {
		return holdBufFull
	}
	h.bySender[key] = append(queue, heldRetrieved{
		msg:         msg,
		size:        size,
		heldAt:      now,
		lastPathReq: now,
	})
	h.count++
	h.bytes += size
	return holdBufAdded
}

func (h *retrievedHoldBuffer) hasSender(sender []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bySender[hex.EncodeToString(sender)]) > 0
}

func (h *retrievedHoldBuffer) release(sender []byte, known *rns.KnownIdentity) (startWorker bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(sender)
	queue := h.bySender[key]
	if len(queue) == 0 {
		return false
	}
	delete(h.bySender, key)
	for _, item := range queue {
		item.known = known
		h.ready = append(h.ready, item)
	}
	if h.draining {
		return false
	}
	h.draining = true
	return true
}

func (h *retrievedHoldBuffer) nextReady() (heldRetrieved, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ready) == 0 {
		h.ready = nil
		h.draining = false
		return heldRetrieved{}, false
	}
	item := h.ready[0]
	h.ready[0] = heldRetrieved{}
	h.ready = h.ready[1:]
	h.count--
	h.bytes -= item.size
	return item, true
}

func (h *retrievedHoldBuffer) expire(now time.Time) []heldRetrieved {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := now.Add(-h.ttl)
	var expired []heldRetrieved
	for key, queue := range h.bySender {
		kept := queue[:0:0]
		for _, item := range queue {
			if item.heldAt.After(cutoff) {
				kept = append(kept, item)
				continue
			}
			expired = append(expired, item)
			h.count--
			h.bytes -= item.size
		}
		if len(kept) == 0 {
			delete(h.bySender, key)
		} else {
			h.bySender[key] = kept
		}
	}
	return expired
}

func (h *retrievedHoldBuffer) sendersDueForPathRetry(now time.Time) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	var due [][]byte
	for key, queue := range h.bySender {
		if len(queue) == 0 {
			continue
		}
		if now.Sub(queue[0].lastPathReq) >= h.retry {
			for i := range queue {
				queue[i].lastPathReq = now
			}
			h.bySender[key] = queue
			due = append(due, append([]byte(nil), queue[0].msg.SourceHash...))
		}
	}
	return due
}

// retrievedStampBudget implements a per-sender token bucket for FAILED
// inbound stamp validations on propagation-retrieved messages.
type retrievedStampBudget struct {
	mu      sync.Mutex
	entries map[string]*stampBudgetEntry
}

type stampBudgetEntry struct {
	tokens   int
	refillAt time.Time
}

func newRetrievedStampBudget() *retrievedStampBudget {
	return &retrievedStampBudget{
		entries: make(map[string]*stampBudgetEntry),
	}
}

func (b *retrievedStampBudget) allow(sender []byte, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[hex.EncodeToString(sender)]
	if !ok {
		return true
	}
	e.refill(now)
	return e.tokens > 0
}

func (b *retrievedStampBudget) charge(sender []byte, now time.Time) {
	key := hex.EncodeToString(sender)
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key]
	if !ok {
		if len(b.entries) >= retrievedStampBudgetMax {
			b.evictLocked(now)
		}
		e = &stampBudgetEntry{tokens: retrievedStampFailureBurst, refillAt: now}
		b.entries[key] = e
	}
	e.refill(now)
	if e.tokens > 0 {
		e.tokens--
	}
}

func (e *stampBudgetEntry) refill(now time.Time) {
	if e.tokens >= retrievedStampFailureBurst {
		e.refillAt = now
		return
	}
	elapsed := now.Sub(e.refillAt)
	if elapsed < retrievedStampFailureRefill {
		return
	}
	gained := int(elapsed / retrievedStampFailureRefill)
	e.tokens += gained
	if e.tokens >= retrievedStampFailureBurst {
		e.tokens = retrievedStampFailureBurst
		e.refillAt = now
	} else {
		e.refillAt = e.refillAt.Add(time.Duration(gained) * retrievedStampFailureRefill)
	}
}

func (b *retrievedStampBudget) evictLocked(now time.Time) {
	for k, e := range b.entries {
		e.refill(now)
		if e.tokens >= retrievedStampFailureBurst {
			delete(b.entries, k)
		}
	}
	if len(b.entries) >= retrievedStampBudgetMax {
		for k := range b.entries {
			delete(b.entries, k)
			break
		}
	}
}
