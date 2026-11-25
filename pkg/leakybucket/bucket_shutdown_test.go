package leakybucket

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// newShutdownTestFactory builds a counter factory wired to response/retDone
// exactly like loadBucketFactoriesFromFile does in production.
func newShutdownTestFactory(response chan pipeline.Event, retDone <-chan struct{}) (*BucketFactory, error) {
	f := &BucketFactory{
		Spec: BucketSpec{
			Name:        "test_shutdown_bucket",
			Description: "counter bucket for shutdown tests",
			Type:        "counter",
			Capacity:    -1,
			Duration:    "1h",
			Filter:      "true",
		},
		ret:     response,
		retDone: retDone,
	}

	if err := f.LoadBucket(); err != nil {
		return nil, err
	}

	return f, nil
}

// TestLeakRoutineExitsWhenOutputReadersAreGone reproduces the reload hang of
// #4748 at unit scale: two live buckets sharing the buffer-1 AllOut channel,
// the output readers stopped, then the context canceled. On master, the
// first cleanup event fills the buffer and the second bucket parks in
// LeakRoutine forever. With outDone closed by shutdown before cancel, both
// goroutines must exit.
func TestLeakRoutineExitsWhenOutputReadersAreGone(t *testing.T) {
	response := make(chan pipeline.Event, 1)
	retDone := make(chan struct{})

	holder, err := newShutdownTestFactory(response, retDone)
	require.NoError(t, err)

	bucketStore := NewBucketStore()

	pourCtx, pourCancel := context.WithCancel(t.Context())
	defer pourCancel()

	// create two live buckets, like two IPs hitting the same scenario
	for _, key := range []string{"bucket-1", "bucket-2"} {
		bucket, err := LoadOrStoreBucketFromHolder(pourCtx, key, bucketStore, holder, pipeline.LIVE)
		require.NoError(t, err)
		require.NotNil(t, bucket)
	}

	require.Equal(t, 2, bucketStore.Len())

	// shutdown order, as in ShutdownCrowdsecRoutines: readers die first,
	// then outDone is closed, then the buckets' context is canceled.
	close(retDone)
	pourCancel()

	// both routines must be gone: their done channel is closed on return
	for _, key := range []string{"bucket-1", "bucket-2"} {
		bucket, ok := bucketStore.Load(key)
		require.True(t, ok, "bucket %s still in store", key)

		select {
		case <-bucket.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("bucket %s LeakRoutine is still parked on its final send after shutdown", key)
		}
	}
}

// TestLeakRoutineStillDeliversWhileReadersLive pins the other side of the
// contract: outDone must not drop events while the output loop is alive, or
// a bucket canceled by the garbage collector could vanish without telling
// the store to delete it.
func TestLeakRoutineStillDeliversWhileReadersLive(t *testing.T) {
	response := make(chan pipeline.Event, 1)
	retDone := make(chan struct{})
	defer close(retDone)

	holder, err := newShutdownTestFactory(response, retDone)
	require.NoError(t, err)

	bucketStore := NewBucketStore()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	bucket, err := LoadOrStoreBucketFromHolder(ctx, "bucket-1", bucketStore, holder, pipeline.LIVE)
	require.NoError(t, err)
	require.NotNil(t, bucket)

	// reader alive, outDone not closed: the final event must be delivered
	cancel()

	select {
	case ev := <-response:
		require.Equal(t, pipeline.OVFLW, ev.Type)
		require.Equal(t, "bucket-1", ev.Overflow.Mapkey)
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup event was dropped while the output reader was still alive")
	}
}
