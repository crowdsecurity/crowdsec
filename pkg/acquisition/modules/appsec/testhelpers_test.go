package appsecacquisition

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// sharedChallengeRuntime lazily creates a single ChallengeRuntime for the
// whole package test run. NewChallengeRuntime runs the obfuscator WASM to
// generate a challenge JS bundle (~15-20s), so spinning one up per test is
// prohibitively slow and unnecessary for integration tests that don't mutate
// runtime-level state.
var (
	sharedChallengeRuntimeOnce sync.Once
	sharedChallengeRuntimeInst *challenge.ChallengeRuntime
	sharedChallengeRuntimeErr  error
)

func getSharedChallengeRuntime(t *testing.T) *challenge.ChallengeRuntime {
	t.Helper()
	sharedChallengeRuntimeOnce.Do(func() {
		sharedChallengeRuntimeInst, sharedChallengeRuntimeErr = challenge.NewChallengeRuntime(context.Background())
	})
	require.NoError(t, sharedChallengeRuntimeErr)
	return sharedChallengeRuntimeInst
}
