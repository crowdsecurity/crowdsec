package leakybucket

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func expectBucketCount(bucketStore *BucketStore, expected int) error {
	count := bucketStore.Len()

	if count != expected {
		return fmt.Errorf("expected %d live buckets, got %d", expected, count)
	}

	return nil
}

func TestGCandDump(t *testing.T) {
	var (
		bucketStore = NewBucketStore()
		ctx         = t.Context()
	)

	Holders := []BucketFactory{
		// one overflowing soon + bh
		{
			Spec: BucketSpec{
				Name:        "test_counter_fast",
				Description: "test_counter_fast",
				Debug:       true,
				Type:        "counter",
				Capacity:    -1,
				Duration:    "0.5s",
				Blackhole:   "1m",
				Filter:      "true",
			},
		},
		// one long counter
		{
			Spec: BucketSpec{
				Name:        "test_counter_slow",
				Description: "test_counter_slow",
				Debug:       true,
				Type:        "counter",
				Capacity:    -1,
				Duration:    "10m",
				Filter:      "true",
			},
		},
		// slow leaky
		{
			Spec: BucketSpec{
				Name:        "test_leaky_slow",
				Description: "test_leaky_slow",
				Debug:       true,
				Type:        "leaky",
				Capacity:    5,
				LeakSpeed:   "10m",
				Filter:      "true",
			},
		},
	}

	for idx := range Holders {
		if err := Holders[idx].LoadBucket(); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}

		if err := Holders[idx].Validate(); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Info("Pouring to bucket")

	in := pipeline.Event{Parsed: map[string]string{"something": "something"}}
	// pour an item that will go to leaky + counter
	ok, err := PourItemToHolders(ctx, in, Holders, bucketStore, nil)
	if err != nil {
		t.Fatalf("while pouring item: %s", err)
	}

	if !ok {
		t.Fatal("didn't pour item")
	}

	time.Sleep(2 * time.Second)

	if err := expectBucketCount(bucketStore, 3); err != nil {
		t.Fatal(err)
	}

	log.Info("Bucket GC")

	// call garbage collector
	GarbageCollectBuckets(time.Now().UTC(), bucketStore)

	if err := expectBucketCount(bucketStore, 1); err != nil {
		t.Fatal(err)
	}
}

// TestRaceSetMetaAndDistinct demonstrates a known data race between the pour goroutine
// writing to evt.Meta (via SetMeta in a filter) and a bucket goroutine reading
// from evt.Meta (via a distinct expression).
//
// The race occurs because events are sent to bucket goroutines by pointer without
// cloning the underlying maps. When the pour goroutine continues evaluating filters
// for subsequent holders (which may call SetMeta), it writes to the same Meta map
// that a previously-matched bucket's goroutine is concurrently reading.
//
// To verify the race still exists, run:
//
//	go test -race -run TestRaceSetMetaAndDistinct ./pkg/leakybucket/ -count=1 -failfast
//
// See also: pkg/leakybucket/manager_run.go PourItemToBucket() line ~136
func TestRaceSetMetaAndDistinct(t *testing.T) {
	t.Skip("Known race condition: concurrent Meta map access between pour and bucket goroutines (see comment above)")

	if err := exprhelpers.Init(nil); err != nil {
		t.Fatal(err)
	}

	bucketStore := NewBucketStore()
	ctx := t.Context()

	// holders[0]: leaky with distinct that READS evt.Meta
	// holders[1]: leaky with filter that WRITES to evt.Meta via SetMeta
	//
	// The pour loop processes holders sequentially. After sending the event
	// to bucket[0] (unbuffered channel), the pour goroutine continues to
	// evaluate holders[1]'s filter (which calls SetMeta). Meanwhile,
	// bucket[0]'s goroutine processes OnBucketPour and evaluates the
	// distinct expression (which reads evt.Meta). Both access the same
	// underlying map concurrently.
	holders := []BucketFactory{
		{
			Spec: BucketSpec{
				Name:        "test_read_meta",
				Description: "bucket with distinct that reads Meta",
				Type:        "leaky",
				Capacity:    100,
				LeakSpeed:   "1m",
				Filter:      "true",
				Distinct:    `evt.Meta.target_techno`,
			},
		},
		{
			Spec: BucketSpec{
				Name:        "test_write_meta",
				Description: "bucket with filter that writes Meta",
				Type:        "leaky",
				Capacity:    100,
				LeakSpeed:   "1m",
				Filter:      `evt.SetMeta("target_techno", "test_value")`,
			},
		},
	}

	for idx := range holders {
		if err := holders[idx].LoadBucket(); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(holders), err)
		}
		if err := holders[idx].Validate(); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(holders), err)
		}
	}

	// Pour many events to trigger the race window.
	// The race occurs between the pour goroutine (SetMeta write) and
	// the bucket goroutine (distinct expression read) on the shared Meta map.
	for i := 0; i < 1000; i++ {
		in := pipeline.Event{
			Parsed: map[string]string{"something": "something"},
			Meta:   map[string]string{"source_ip": "1.2.3.4"},
		}
		_, err := PourItemToHolders(ctx, in, holders, bucketStore, nil)
		if err != nil {
			t.Fatalf("while pouring item %d: %s", i, err)
		}
		// Yield to give bucket goroutines a chance to run concurrently
		runtime.Gosched()
	}

	// Give bucket goroutines time to finish processing
	time.Sleep(500 * time.Millisecond)
}

func TestShutdownBuckets(t *testing.T) {
	var (
		bucketStore = NewBucketStore()
		Holders     = []BucketFactory{
			// one long counter
			{
				Spec: BucketSpec{
					Name:        "test_counter_slow",
					Description: "test_counter_slow",
					Debug:       true,
					Type:        "counter",
					Capacity:    -1,
					Duration:    "10m",
					Filter:      "true",
				},
			},
			// slow leaky
			{
				Spec: BucketSpec{
					Name:        "test_leaky_slow",
					Description: "test_leaky_slow",
					Debug:       true,
					Type:        "leaky",
					Capacity:    5,
					LeakSpeed:   "10m",
					Filter:      "true",
				},
			},
		}
	)

	for idx := range Holders {
		if err := Holders[idx].LoadBucket(); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}

		if err := Holders[idx].Validate(); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Info("Pouring to bucket")

	in := pipeline.Event{Parsed: map[string]string{"something": "something"}}
	// pour an item that will go to leaky + counter
	ctx, cancel := context.WithCancel(t.Context())
	ok, err := PourItemToHolders(ctx, in, Holders, bucketStore, nil)
	if err != nil {
		t.Fatalf("while pouring item : %s", err)
	}

	if !ok {
		t.Fatal("didn't pour item")
	}

	time.Sleep(1 * time.Second)

	if err := expectBucketCount(bucketStore, 2); err != nil {
		t.Fatal(err)
	}

	cancel()

	time.Sleep(2 * time.Second)

	if err := expectBucketCount(bucketStore, 2); err != nil {
		t.Fatal(err)
	}
}
