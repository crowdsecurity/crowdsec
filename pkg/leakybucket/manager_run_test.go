package leakybucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

func expectBucketCount(buckets *Buckets, expected int) error {
	count := 0
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
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
		buckets *Buckets   = NewBuckets()
		tomb    *tomb.Tomb = &tomb.Tomb{}
	)

	var Holders = []BucketFactory{
		//one overflowing soon + bh
		BucketFactory{
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
		//one long counter
		BucketFactory{
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
		//slow leaky
		BucketFactory{
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
		if err := LoadBucket(&Holders[idx], tomb); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}
		if err := ValidateFactory(&Holders[idx]); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Printf("Pouring to bucket")

	var in = types.Event{Parsed: map[string]string{"something": "something"}}
	//pour an item that will go to leaky + counter
	ok, err := PourItemToHolders(in, Holders, buckets)
	if err != nil {
		t.Fatalf("while pouring item : %s", err)
	}
	if !ok {
		t.Fatalf("didn't pour item")
	}

	time.Sleep(2 * time.Second)

	if err := expectBucketCount(buckets, 3); err != nil {
		t.Fatal(err)
	}
	log.Printf("Bucket GC")

	//call garbage collector
	if err := GarbageCollectBuckets(time.Now().UTC(), buckets); err != nil {
		t.Fatalf("failed to garbage collect buckets : %s", err)
	}

	if err := expectBucketCount(buckets, 1); err != nil {
		t.Fatal(err)
	}

	log.Printf("Dumping buckets state")
	//dump remaining buckets
	if _, err := DumpBucketsStateAt(time.Now().UTC(), ".", buckets); err != nil {
		t.Fatalf("failed to dump buckets : %s", err)
	}
}

func TestShutdownBuckets(t *testing.T) {
	var (
		buckets *Buckets = NewBuckets()
		Holders          = []BucketFactory{
			//one long counter
			BucketFactory{
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
			//slow leaky
			BucketFactory{
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
		tomb *tomb.Tomb = &tomb.Tomb{}
	)

	for idx := range Holders {
		if err := LoadBucket(&Holders[idx], tomb); err != nil {
			t.Fatalf("while loading (%d/%d): %s", idx, len(Holders), err)
		}
		if err := ValidateFactory(&Holders[idx]); err != nil {
			t.Fatalf("while validating (%d/%d): %s", idx, len(Holders), err)
		}
	}

	log.Printf("Pouring to bucket")

	var in = types.Event{Parsed: map[string]string{"something": "something"}}
	//pour an item that will go to leaky + counter
	ok, err := PourItemToHolders(in, Holders, buckets)
	if err != nil {
		t.Fatalf("while pouring item : %s", err)
	}
	if !ok {
		t.Fatalf("didn't pour item")
	}

	time.Sleep(1 * time.Second)

	if err := expectBucketCount(buckets, 2); err != nil {
		t.Fatal(err)
	}
	if err := ShutdownAllBuckets(buckets); err != nil {
		t.Fatalf("while shuting down buckets : %s", err)
	}
	time.Sleep(2 * time.Second)
	if err := expectBucketCount(buckets, 2); err != nil {
		t.Fatal(err)
	}

}
