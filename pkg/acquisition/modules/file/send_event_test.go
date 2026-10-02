package fileacquisition

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Shutdown cancels the acquisition context while the pipeline may already have stopped reading out.
// A plain send would block forever there, so Stream would not return. sendEvent must give up and drop the event.
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
