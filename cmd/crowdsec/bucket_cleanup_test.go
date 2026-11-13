package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const blackholeScenario = `
type: leaky
name: test/blackhole
description: blackhole
filter: "true"
groupby: evt.Meta.source_ip
capacity: 1
leakspeed: 10s
blackhole: 10m
`

func blackholeLine(t *testing.T, offset time.Duration) pipeline.Event {
	t.Helper()

	ts, err := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(offset).MarshalText()
	require.NoError(t, err)

	return pipeline.Event{
		Type:          pipeline.LOG,
		Process:       true,
		ExpectMode:    pipeline.TIMEMACHINE,
		MarshaledTime: string(ts),
		Meta:          map[string]string{"source_ip": "10.0.0.1"},
	}
}

// A blackholed bucket's cleanup event reaches the output routine at some point
// after the bucket died: by then the next bucket for the same key may already
// hold events, and it must survive the cleanup.
func TestBlackholeCleanupKeepsNextBucket(t *testing.T) {
	tests := []struct {
		name         string
		cleanupFirst bool // cleanup handled before the next bucket is created
		bucketsLeft  int  // right after the cleanup
	}{
		{name: "cleanup before next bucket removes the dead one", cleanupFirst: true, bucketsLeft: 0},
		{name: "late cleanup keeps the next bucket", cleanupFirst: false, bucketsLeft: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blackhole.yaml")
			require.NoError(t, os.WriteFile(path, []byte(blackholeScenario), 0o600))

			factories, out, err := leakybucket.LoadBuckets(&csconfig.CrowdsecServiceCfg{}, &cwhub.Hub{},
				[]*cwhub.Item{{State: cwhub.ItemState{LocalPath: path}}}, false)
			require.NoError(t, err)

			store := leakybucket.NewBucketStore()

			pour := func(offset time.Duration) {
				_, err := leakybucket.PourItemToHolders(t.Context(), blackholeLine(t, offset), factories, store, nil)
				require.NoError(t, err)
			}

			next := func() pipeline.Event {
				select {
				case evt := <-out:
					return evt
				case <-time.After(5 * time.Second):
					require.FailNow(t, "no overflow")
				}

				return pipeline.Event{}
			}

			// handled like the output routine does, synchronously
			handleCleanup := func(evt pipeline.Event) {
				ch := make(chan pipeline.Event)
				dying := make(chan struct{})
				done := make(chan error)

				go func() {
					done <- outputLoop(t.Context(), 0, ch, store, nil, nil, &alertBuffer{}, 1, dying)
				}()

				ch <- evt
				close(dying)
				require.NoError(t, <-done)
				require.Equal(t, tc.bucketsLeft, store.Len())
			}

			pour(0)
			pour(time.Second)
			require.NotNil(t, next().Overflow.Alert, "first overflow should go through")

			pour(2 * time.Second)
			pour(3 * time.Second)

			cleanup := next()
			require.Nil(t, cleanup.Overflow.Alert, "second overflow should be blackholed")
			require.NotEmpty(t, cleanup.Overflow.Mapkey)

			if tc.cleanupFirst {
				handleCleanup(cleanup)
			}

			// out of the blackhole: a new bucket for the same key
			pour(30 * time.Minute)

			if !tc.cleanupFirst {
				handleCleanup(cleanup)
			}

			pour(30*time.Minute + time.Second)
			require.NotNil(t, next().Overflow.Alert, "the burst after the blackhole was lost")
		})
	}
}
