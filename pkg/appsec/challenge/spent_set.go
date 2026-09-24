// spent_set.go is the single-use store that eliminates challenge replay: each
// validated submission burns its per-challenge nonce `r`, so a replay fails.
package challenge

import (
	"container/list"
	"sync"
	"time"
)

// spentSetDefaultMaxEntries is a deep DoS backstop. Growth is sig+PoW-gated and
// TTL-bounded (ticketAgeBackstop), so steady-state stays far below this. If the
// cap is ever hit, the oldest (maybe still-live) `r` is evicted, letting that
// one submission replay once — acceptable at this size.
const spentSetDefaultMaxEntries = 1_000_000

type spentEntry struct {
	r         string
	expiresAt time.Time
}

// spentSet records consumed per-challenge nonces. Safe for concurrent use.
//
// The store is a plain map plus an insertion-ordered list, grown on demand:
// sizing it for maxEntries up front would cost ~70MB of resident memory on a
// runtime that never sees a single challenge. Entries are only ever inserted
// (a hit means replay, and doesn't refresh the entry), so insertion order is
// also expiry order and eviction order — the list front is always both the
// oldest and the soonest to expire.
type spentSet struct {
	// mu makes the lookup/insert pair in checkAndInsert atomic.
	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List

	// maxEntries is the configured cap, retained for introspection.
	maxEntries int
}

func newSpentSet(maxEntries int) *spentSet {
	return &spentSet{
		items:      make(map[string]*list.Element),
		order:      list.New(),
		maxEntries: maxEntries,
	}
}

// checkAndInsert atomically records `r` as spent, returning true if it was
// fresh and false if already present (replay). TTL matches the freshness
// window, so an expired (absent) entry is also one the caller rejects anyway.
func (s *spentSet) checkAndInsert(r string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	s.evictExpired(now)

	if _, ok := s.items[r]; ok {
		return false
	}

	// Cap reached with nothing expired to reclaim: drop the oldest.
	if s.maxEntries > 0 && s.order.Len() >= s.maxEntries {
		s.remove(s.order.Front())
	}

	s.items[r] = s.order.PushBack(&spentEntry{r: r, expiresAt: now.Add(ttl)})

	return true
}

// evictExpired drops entries from the front of the list until it finds a live
// one. Callers hold mu.
func (s *spentSet) evictExpired(now time.Time) {
	for e := s.order.Front(); e != nil; e = s.order.Front() {
		if e.Value.(*spentEntry).expiresAt.After(now) {
			return
		}

		s.remove(e)
	}
}

// remove unlinks one entry from both the list and the map. Callers hold mu.
func (s *spentSet) remove(e *list.Element) {
	s.order.Remove(e)
	delete(s.items, e.Value.(*spentEntry).r)
}

// len reports how many entries are currently held, expired ones included.
func (s *spentSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.order.Len()
}
