package challenge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestClose_StopsPreWarmer is the regression guard for the pre-warmer goroutine
// leak: before the fix, Close() closed the wazero runtime but left
// dynamicModulePreWarmer ticking against it forever (logging
// "runtime closed with exit_code(0)" once per epoch, per leaked goroutine, and
// growing on every reload). goleak asserts the goroutine is gone after Close().
func TestClose_StopsPreWarmer(t *testing.T) {
	if testing.Short() {
		t.Skip("constructor pays the initial dynamic-module obfuscation cost (~seconds); skipped in -short")
	}

	rt, err := NewChallengeRuntime(t.Context(),
		WithMasterSecret([]byte("0123456789abcdef0123456789abcdef")),
	)
	require.NoError(t, err)
	require.NotNil(t, rt.preWarmCancel, "constructor must wire the pre-warmer cancel func")

	// Let the pre-warmer goroutine reach its select before we stop it.
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	require.NoError(t, rt.Close(t.Context()))
	require.Less(t, time.Since(start), time.Second,
		"Close() cancels the pre-warmer and returns without waiting on it")

	// No lingering pre-warmer (or wazero runtime) goroutines after Close().
	goleak.VerifyNone(t)
}
