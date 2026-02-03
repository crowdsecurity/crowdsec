package leakybucket

import (
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

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
			Name:        "test_counter_fast",
			Description: "test_counter_fast",
			Debug:       true,
			Type:        "counter",
			Capacity:    -1,
			Duration:    "0.5s",
			Blackhole:   "1m",
			Filter:      "true",
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

func TestShutdownBuckets(t *testing.T) {
	var (
		bucketStore = NewBucketStore()
		Holders     = []BucketFactory{
			// one long counter
			{
				Name:        "test_counter_slow",
				Description: "test_counter_slow",
				Debug:       true,
				Type:        "counter",
				Capacity:    -1,
				Duration:    "10m",
				Filter:      "true",
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
