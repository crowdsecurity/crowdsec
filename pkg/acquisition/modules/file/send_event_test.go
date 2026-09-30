package fileacquisition

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// A canceled context unblocks a send onto a channel nobody is reading, and the event is not delivered.
func TestSendEventUnblocksWhenContextCanceled(t *testing.T) {
	out := make(chan pipeline.Event)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	returned := make(chan bool, 1)
	go func() {
		returned <- sendEvent(ctx, out, pipeline.Event{Line: pipeline.Line{Raw: "kept"}})
	}()

	cancel()

	select {
	case sent := <-returned:
		require.False(t, sent)
	case <-time.After(2 * time.Second):
		t.Fatal("sendEvent stayed blocked after cancel")
	}

	select {
	case evt := <-out:
		t.Fatalf("event sent after cancel: %q", evt.Line.Raw)
	default:
	}
}
