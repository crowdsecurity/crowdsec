package leakybucket

import (
	"sync"
)

// BucketGate coordinates pour creation and dump/GC operations that
// require a consistent view of all buckets.
//
// It provides two guarantees:
//  1) While a dump/GC holds the exclusive gate, no new pours can start.
//  2) A dump/GC can wait for all pours that were already in-flight to finish.
type BucketGate struct {
	gateMu sync.RWMutex
	pourWG sync.WaitGroup
}

// BeginPour enters the shared (non-exclusive) section for a pour.
//
// It blocks if an exclusive operation (dump/GC) is in progress.
// It returns a function that must be called exactly once, typically via defer().
//
// done := gate.BeginPour()
// defer done()
// ... do the pour ...
func (g *BucketGate) BeginPour() (done func()) {
	g.gateMu.RLock()
	g.pourWG.Add(1)

	return func() {
		g.pourWG.Done()
		g.gateMu.RUnlock()
	}
}

// WithPoursBlocked prevents pours from running and waits for the existing ones
// to drain, then calls fn.
//
// gate.WithPoursBlocked(func() {
//     ... GC, iterate, etc. ...
// })
func (g *BucketGate) WithPoursBlocked(fn func()) {
	g.gateMu.Lock()
	defer g.gateMu.Unlock()

	g.pourWG.Wait()

	fn()
}
