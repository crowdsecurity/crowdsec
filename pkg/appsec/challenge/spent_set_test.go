package challenge

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
// guards the store's own expiry behaviour.)
func TestSpentSet_Expiry(t *testing.T) {
	s := newSpentSet(spentSetDefaultMaxEntries)

	assert.True(t, s.checkAndInsert("r-exp", 20*time.Millisecond))
	assert.False(t, s.checkAndInsert("r-exp", 20*time.Millisecond))

	time.Sleep(40 * time.Millisecond)

	assert.True(t, s.checkAndInsert("r-exp", 20*time.Millisecond),
		"entry must be re-accepted after its TTL expires")
}
