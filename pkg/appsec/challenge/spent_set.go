// spent_set.go is the single-use store that eliminates challenge replay: each
// validated submission burns its per-challenge nonce `r`, so a replay fails.
package challenge

import (
	"sync"
	"time"

	"github.com/bluele/gcache"
)

// spentSetMaxEntries is a deep DoS backstop. Growth is sig+PoW-gated and
// TTL-bounded (ticketAgeBackstop), so steady-state stays far below this. If the
// cap is ever hit, LRU evicts the oldest (maybe still-live) `r`, letting that
// one submission replay once — acceptable at this size.
const spentSetMaxEntries = 1_000_000

// spentSet records consumed per-challenge nonces. Safe for concurrent use.
type spentSet struct {
	// mu makes the Has/Set pair in checkAndInsert atomic (gcache locks each op
	// independently, which alone wouldn't stop two concurrent replays winning).
	mu    sync.Mutex
	cache gcache.Cache
}

func newSpentSet() *spentSet {
	return &spentSet{cache: gcache.New(spentSetMaxEntries).LRU().Build()}
}

// checkAndInsert atomically records `r` as spent, returning true if it was
// fresh and false if already present (replay). TTL matches the freshness
// window, so an expired (absent) entry is also one the caller rejects anyway.
func (s *spentSet) checkAndInsert(r string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cache.Has(r) {
		return false
	}

	// SetWithExpire can't fail here: we configure no serialization/eviction hook.
	_ = s.cache.SetWithExpire(r, struct{}{}, ttl)

	return true
}
