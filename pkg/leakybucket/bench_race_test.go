package leakybucket

import (
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// benchEvent returns a fresh, realistic parsed HTTP event. Meta is a single map
// that PourItemToHolders will share (by reference) across every matching bucket.
func benchEvent(now time.Time) pipeline.Event {
	return pipeline.Event{
		Time: now,
		Meta: map[string]string{
			"source_ip":       "1.2.3.4",
			"service":         "http",
			"log_type":        "http_access-log",
			"http_status":     "404",
			"http_path":       "/wp-admin/",
			"http_verb":       "GET",
			"http_user_agent": "curl/8.0",
			"http_host":       "example.com",
			"machine":         "test",
			"datasource_path": "/var/log/traefik/access.log",
			"datasource_type": "file",
			"k1":              "v1",
			"k2":              "v2",
			"k3":              "v3",
		},
	}
}

// runPourBenchmark drives PourItemToHolders against `readers` trigger scenarios
// (each overflows immediately and reads evt.Meta while building its alert). If
// withWriter is true, a final scenario whose filter mutates the shared event via
// evt.SetMeta(...) is appended — reproducing the crowdsecurity/http-technology-probing
// side effect and the crowdsecurity/crowdsec#4459 data race.
func runPourBenchmark(b *testing.B, readers int, withWriter bool) {
	b.Helper()

	// keep the overflow alert validation noise out of the benchmark output
	oldLevel := log.GetLevel()
	log.SetLevel(log.PanicLevel)
	defer log.SetLevel(oldLevel)

	// response collects overflows emitted by every bucket (AllOut). It must be
	// drained continuously, otherwise the overflowing trigger goroutines block
	// on the send *after* having read the shared map.
	response := make(chan pipeline.Event, 4096)

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-response:
			}
		}
	}()
	defer close(stop)

	holders := make([]BucketFactory, 0, readers+1)

	// Readers: each is a trigger that overflows immediately and reads evt.Meta
	// while building the alert.
	for i := range readers {
		holders = append(holders, BucketFactory{
			Spec: BucketSpec{
				Name:        fmt.Sprintf("reader_%d", i),
				Description: "reads shared Meta on overflow",
				Type:        "trigger",
				Filter:      "true",
			},
		})
	}

	if withWriter {
		// The writer last: its filter has a side effect on the shared event, just
		// like crowdsecurity/http-technology-probing's `evt.SetMeta(...)`.
		holders = append(holders, BucketFactory{
			Spec: BucketSpec{
				Name:        "writer",
				Description: "mutates shared Meta from its filter",
				Type:        "trigger",
				Filter:      `evt.SetMeta("injected", "1")`,
			},
		})
	}

	for idx := range holders {
		holders[idx].ret = response
		if err := holders[idx].LoadBucket(); err != nil {
			b.Fatalf("while loading holder %d: %s", idx, err)
		}

		if err := holders[idx].Validate(); err != nil {
			b.Fatalf("while validating holder %d: %s", idx, err)
		}
	}

	ctx := b.Context()
	bucketStore := NewBucketStore()
	now := time.Now().UTC()

	for b.Loop() {
		evt := benchEvent(now)
		if _, err := PourItemToHolders(ctx, evt, holders, bucketStore, nil); err != nil {
			b.Fatalf("while pouring item: %s", err)
		}
	}
}

// BenchmarkPourSharedMetaRace reproduces the data race reported in
// crowdsecurity/crowdsec#4459.
//
// Root cause: PourItemToHolders pours a single parsed event into every matching
// scenario, but Event.Meta is a map (reference type) and the pour path only
// makes a shallow struct copy (pipeline.Queue.Add). Every bucket queue across
// all matching scenarios therefore ends up sharing the *same* Meta map.
//
// It wires up several "reader" trigger scenarios followed by a "writer" whose
// filter mutates the shared map via evt.SetMeta(...). When runPour evaluates the
// writer's filter (a map write) while an already-poured reader bucket iterates
// the same map during overflow (a map read), the Go runtime aborts with:
//
//	fatal error: concurrent map iteration and map write
//	fatal error: concurrent map read and map write
//
// Run as a race reproducer (reports a data race before the fix, clean after):
//
//	go test -tags 'netgo,osusergo,expr_debug,nomsgpack' -race \
//	    -run='^$' -bench=BenchmarkPourSharedMetaRace ./pkg/leakybucket/
func BenchmarkPourSharedMetaRace(b *testing.B) {
	runPourBenchmark(b, 8, true)
}

// BenchmarkPourNoSideEffect is the same pour workload without the side-effecting
// filter, so no map is ever mutated after being poured. It is race-free both
// before and after the #4459 fix, which makes it the apples-to-apples way to
// measure the fix's only cost: the per-pour CopyForBucket clone. Compare ns/op
// and allocs/op with and without the fix applied:
//
//	go test -tags 'netgo,osusergo,expr_debug,nomsgpack' \
//	    -run='^$' -bench=BenchmarkPourNoSideEffect -benchmem ./pkg/leakybucket/
func BenchmarkPourNoSideEffect(b *testing.B) {
	runPourBenchmark(b, 8, false)
}
