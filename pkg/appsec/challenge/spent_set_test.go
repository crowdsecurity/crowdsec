package challenge

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpentSet_CheckAndInsert(t *testing.T) {
	s := newSpentSet(spentSetDefaultMaxEntries)

	// First insert of a fresh r succeeds.
	assert.True(t, s.checkAndInsert("r1", time.Minute))
	// Replay of the same r is rejected.
	assert.False(t, s.checkAndInsert("r1", time.Minute))
	// A different r is independent.
	assert.True(t, s.checkAndInsert("r2", time.Minute))
}

// TestSpentSet_ConcurrentSameKey asserts the check-and-insert pair is atomic:
// when N goroutines race to burn the same r, exactly one wins. Run with -race.
func TestSpentSet_ConcurrentSameKey(t *testing.T) {
	s := newSpentSet(spentSetDefaultMaxEntries)

	const goroutines = 64
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if s.checkAndInsert("same-r", time.Minute) {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), wins, "exactly one goroutine must win the single-use race")
}

// TestSpentSet_Expiry asserts an entry is re-accepted after its TTL lapses.
// (In production the freshness check rejects such an aged r anyway; this only
// guards the store's own expiry behavior.)
func TestSpentSet_Expiry(t *testing.T) {
	s := newSpentSet(spentSetDefaultMaxEntries)

	assert.True(t, s.checkAndInsert("r-exp", 20*time.Millisecond))
	assert.False(t, s.checkAndInsert("r-exp", 20*time.Millisecond))

	time.Sleep(40 * time.Millisecond)

	assert.True(t, s.checkAndInsert("r-exp", 20*time.Millisecond),
		"entry must be re-accepted after its TTL expires")
}

// TestSpentSet_EvictsOldestAtCap asserts the cap is enforced by dropping the
// oldest entry, which may then replay once.
func TestSpentSet_EvictsOldestAtCap(t *testing.T) {
	s := newSpentSet(2)

	require.True(t, s.checkAndInsert("r1", time.Minute))
	require.True(t, s.checkAndInsert("r2", time.Minute))
	require.True(t, s.checkAndInsert("r3", time.Minute))

	require.Equal(t, 2, s.len(), "set must not grow past its cap")
	require.True(t, s.checkAndInsert("r1", time.Minute), "the oldest entry is the one evicted")
	require.False(t, s.checkAndInsert("r3", time.Minute), "the newest entry must still be held")
}

// TestSpentSet_ReclaimsExpired asserts expired entries are dropped rather than
// held until the cap forces an eviction — the set must not grow with traffic
// that has long since aged out.
func TestSpentSet_ReclaimsExpired(t *testing.T) {
	s := newSpentSet(spentSetDefaultMaxEntries)

	for _, r := range []string{"r1", "r2", "r3"} {
		require.True(t, s.checkAndInsert(r, 20*time.Millisecond))
	}

	require.Equal(t, 3, s.len())

	time.Sleep(40 * time.Millisecond)

	require.True(t, s.checkAndInsert("r4", time.Minute))
	require.Equal(t, 1, s.len(), "expired entries must be reclaimed on insert")
}

// TestSpentSet_StartsEmpty guards the reason this store is hand-rolled: a
// freshly built set must not preallocate for maxEntries.
func TestSpentSet_StartsEmpty(t *testing.T) {
	require.Equal(t, 0, newSpentSet(spentSetDefaultMaxEntries).len())
}
