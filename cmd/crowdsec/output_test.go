package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func testOverflow(msg string) pipeline.Event {
	return pipeline.Event{
		Overflow: pipeline.RuntimeAlert{
			Alert: &models.Alert{Message: &msg},
		},
	}
}

// Fails if the output loop is not reading: before #4600 a slow postoverflow
// parser blocked this send, backpressuring the engine up to the appsec responses.
func send(t *testing.T, overflow chan pipeline.Event, evt pipeline.Event) {
	t.Helper()

	select {
	case overflow <- evt:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "output loop stopped reading overflows")
	}
}

func TestOutputLoopSlowPostOverflow(t *testing.T) {
	const queueSize = 4

	ctx := t.Context()

	release := make(chan struct{})
	processed := make(chan pipeline.Event, 16)

	process := func(_ context.Context, evt pipeline.Event) error {
		<-release
		processed <- evt

		return nil
	}

	overflow := make(chan pipeline.Event)
	pendingAlerts := &alertBuffer{}

	loopErr := make(chan error, 1)
	dying := make(chan struct{})

	go func() {
		loopErr <- outputLoop(ctx, 0, overflow, nil, process, nil, pendingAlerts, queueSize, dying)
	}()

	total := queueSize * 4
	for range total {
		send(t, overflow, testOverflow("overflow"))
	}

	close(release)

	require.Eventually(t, func() bool {
		return len(processed) >= queueSize
	}, 5*time.Second, 10*time.Millisecond)

	// the queue is bounded, so the excess was dropped rather than buffered
	time.Sleep(100 * time.Millisecond)
	require.Less(t, len(processed), total, "nothing was dropped")

	close(dying)

	select {
	case err := <-loopErr:
		require.NoError(t, err)
	case <-time.After(postOverflowDrainTimeout + 2*time.Second):
		require.FailNow(t, "output loop did not stop")
	}
}

func TestWarnQueuePressure(t *testing.T) {
	tests := []struct {
		name     string
		depth    int
		size     int
		warned   bool
		expected bool
	}{
		{name: "quiet below the high water mark", depth: 5, size: 100, warned: false, expected: false},
		{name: "warns on crossing 75%", depth: 75, size: 100, warned: false, expected: true},
		{name: "stays warned while still high", depth: 90, size: 100, warned: true, expected: true},
		{
			// a queue hovering just under the high water mark would otherwise
			// re-arm and warn again on every tick
			name: "stays warned between the two marks", depth: 50, size: 100, warned: true, expected: true,
		},
		{name: "re-arms under 25%", depth: 24, size: 100, warned: true, expected: false},
		{name: "re-arms when empty", depth: 0, size: 100, warned: true, expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, warnQueuePressure(tc.depth, tc.size, tc.warned))
		})
	}
}
