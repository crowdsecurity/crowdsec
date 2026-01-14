package leakybucket

import (
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func expectBucketCount(buckets *Buckets, expected int) error {
	count := 0

	buckets.Bucket_map.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count != expected {
		return fmt.Errorf("expected %d live buckets, got %d", expected, count)
	}

	return nil
}

func TestGCandDump(t *testing.T) {
	var (
		buckets = NewBuckets()
		ctx     = t.Context()
	)

	Holders := []BucketFactory{
		// one overflowing soon + bh
		{
			Name:        "test_counter_fast",
			Description: "test_counter_fast",
			Debug:       true,
			Type:        "counter",
			Capacity:    -1,
			Duration:    "0.5s",
			Blackhole:   "1m",
			Filter:      "true",
			wgDumpState: buckets.wgDumpState,
			wgPour:      buckets.wgPour,
		},
		// one long counter
		{
			Name:        "test_counter_slow",
			Description: "test_counter_slow",
			Debug:       true,
			Type:        "counter",
			Capacity:    -1,
			Duration:    "10m",
			Filter:      "true",
			wgDumpState: buckets.wgDumpState,
			wgPour:      buckets.wgPour,
		},
		// slow leaky
		{
			Name:        "test_leaky_slow",
			Description: "test_leaky_slow",
			Debug:       true,
			Type:        "leaky",
			Capacity:    5,
			LeakSpeed:   "10m",
			Filter:      "true",
			wgDumpState: buckets.wgDumpState,
			wgPour:      buckets.wgPour,
		},
	}

	for idx := range Holders {
		if err := LoadBucket(&Holders[idx]); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}

		if err := ValidateFactory(&Holders[idx]); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Info("Pouring to bucket")

	in := pipeline.Event{Parsed: map[string]string{"something": "something"}}
	// pour an item that will go to leaky + counter
	ok, err := PourItemToHolders(ctx, in, Holders, buckets, nil)
	if err != nil {
		t.Fatalf("while pouring item: %s", err)
	}

	if !ok {
		t.Fatal("didn't pour item")
	}

	time.Sleep(2 * time.Second)

	if err := expectBucketCount(buckets, 3); err != nil {
		t.Fatal(err)
	}

	log.Info("Bucket GC")

	// call garbage collector
	GarbageCollectBuckets(time.Now().UTC(), buckets)

	if err := expectBucketCount(buckets, 1); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownBuckets(t *testing.T) {
	var (
		buckets = NewBuckets()
		Holders = []BucketFactory{
			// one long counter
			{
				Name:        "test_counter_slow",
				Description: "test_counter_slow",
				Debug:       true,
				Type:        "counter",
				Capacity:    -1,
				Duration:    "10m",
				Filter:      "true",
				wgDumpState: buckets.wgDumpState,
				wgPour:      buckets.wgPour,
			},
			// slow leaky
			{
				Name:        "test_leaky_slow",
				Description: "test_leaky_slow",
				Debug:       true,
				Type:        "leaky",
				Capacity:    5,
				LeakSpeed:   "10m",
				Filter:      "true",
				wgDumpState: buckets.wgDumpState,
				wgPour:      buckets.wgPour,
			},
		}
	)

	for idx := range Holders {
		if err := LoadBucket(&Holders[idx]); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}

		if err := ValidateFactory(&Holders[idx]); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Info("Pouring to bucket")

	in := pipeline.Event{Parsed: map[string]string{"something": "something"}}
	// pour an item that will go to leaky + counter
	ctx, cancel := context.WithCancel(t.Context())
	ok, err := PourItemToHolders(ctx, in, Holders, buckets, nil)
	if err != nil {
		t.Fatalf("while pouring item : %s", err)
	}

	if !ok {
		t.Fatal("didn't pour item")
	}

	time.Sleep(1 * time.Second)

	if err := expectBucketCount(buckets, 2); err != nil {
		t.Fatal(err)
	}

	cancel()

	time.Sleep(2 * time.Second)

	if err := expectBucketCount(buckets, 2); err != nil {
		t.Fatal(err)
	}
}
