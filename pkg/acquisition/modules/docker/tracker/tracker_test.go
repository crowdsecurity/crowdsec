package tracker

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrackerBasic(t *testing.T) {
	type dummy struct{ value string }

	tr := NewTracker[dummy]()
	assert.Equal(t, 0, tr.Len())

	foo := dummy{value: "foo"}
	tr.Set("a", foo)
	got, ok := tr.Get("a")
	assert.True(t, ok)
	assert.Equal(t, foo.value, got.value)
	assert.Equal(t, foo, got)
	assert.Equal(t, 1, tr.Len())

	// GetAll returns a copy
	all := tr.GetAll()
	assert.Len(t, all, 1)
	all["new"] = dummy{value: "bar"}
	assert.Equal(t, 1, tr.Len(), "modifying snapshot should not affect tracker")

	tr.Delete("a")
	assert.Equal(t, 0, tr.Len())

	// Clear returns the old map
	tr.Set("x", dummy{"x"})
	tr.Set("y", dummy{"y"})
	old := tr.Clear()
	assert.Len(t, old, 2)
	assert.Equal(t, 0, tr.Len())
}

func TestTrackerPointerType(t *testing.T) {
	type dummy struct{ value string }

	tr := NewTracker[*dummy]()
	ptr := &dummy{"foo"}
	tr.Set("a", ptr)
	got, ok := tr.Get("a")
	assert.True(t, ok)
	assert.Equal(t, ptr.value, got.value)
	assert.Same(t, ptr, got)
}

func TestTrackerConcurrentAccess(t *testing.T) {
	type dummy struct{}

	tr := NewTracker[dummy]()
	wg := sync.WaitGroup{}

	workers := 500

	// Writer goroutines
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tr.Set(fmt.Sprintf("key-%04d", i), dummy{})
		}(i)
	}

	// Reader goroutines
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tr.GetAll()
			_, _ = tr.Get("nonexistent-key")
			_ = tr.Len()
		}()
	}

	wg.Wait()

	// Sanity check: we should have at most <workers> entries
	n := tr.Len()
	assert.True(t, n <= workers && n > 0, "unexpected number of entries: %d", n)
}

func TestTrackerLazyInit(t *testing.T) {
	type dummy struct{}

	var tr Tracker[dummy]
	tr.Set("a", dummy{}) // should not panic
	assert.Equal(t, 1, tr.Len())
}

func TestTrackerClear(t *testing.T) {
	type dummy struct {
		value int
	}

	tr := NewTracker[dummy]()
	tr.Set("a", dummy{1})
	tr.Set("b", dummy{2})
	tr.Set("c", dummy{3})

	assert.Equal(t, 3, tr.Len())

	snapshot := tr.Clear()

	assert.Equal(t, 0, tr.Len())

	// Snapshot should still contain old items
	assert.Len(t, snapshot, 3)
	assert.Equal(t, 1, snapshot["a"].value)
	assert.Equal(t, 2, snapshot["b"].value)
	assert.Equal(t, 3, snapshot["c"].value)

	// Modifying snapshot shouldn't affect tracker
	v := snapshot["a"]
	v.value = 42
	snapshot["a"] = v
	assert.Equal(t, 0, tr.Len()) // tracker still empty
	assert.Equal(t, 42, snapshot["a"].value)
}
