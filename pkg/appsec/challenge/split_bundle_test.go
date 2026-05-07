package challenge

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSplitBundle_HookSentinelInBakedBundle is the smallest possible
// regression guard for the split-bundle protocol: the static obfuscated
// bundle that we ship in initial_bundle.js.gz MUST contain a literal
// occurrence of the hook sentinel. Without it, the dynamic key module
// would never find globalThis[hookName] and the challenge would silently
// fail in every browser.
//
// The sentinel survives the high-obfuscation preset only because
// obfuscate.js explicitly registers it via reservedStrings. If someone
// removes that registration this test fires before any user notices.
func TestSplitBundle_HookSentinelInBakedBundle(t *testing.T) {
	rt := &ChallengeRuntime{
		obfuscatedJSCache: make([]obfuscatedScript, 0, challengeJSCacheSize),
	}
	require.NoError(t, rt.seedCacheFromInitialBundle())

	bundle := rt.obfuscatedJSCache[0].Code
	require.NotEmpty(t, bundle)

	count := strings.Count(bundle, hookSentinel)
	assert.GreaterOrEqual(t, count, 1,
		"hook sentinel %q must survive obfuscation in the static bundle (was reservedStrings dropped from obfuscate.js?)",
		hookSentinel)
}

// TestSplitBundle_DynamicModuleEmbedsCurrentEpochKey verifies the dynamic
// module that GetChallengePage will serve actually contains the per-epoch
// key. The output is heavily obfuscated, but the key bytes (hex-encoded)
// MUST be present — if they aren't, the client can't HMAC the ticket.
//
// We do not assert the literal hex string survives intact (the obfuscator
// transforms most string literals); instead we run the obfuscated module
// through a JS engine and check it tries to call our hook with the right
// key. That requires running JS — out of scope here, so we settle for: the
// dynamic module is non-empty, references the hook sentinel, and doesn't
// accidentally leak the hex key as a plain literal.
func TestSplitBundle_DynamicModuleObfuscatesKey(t *testing.T) {
	keys := testKeyRing()
	rt := newChallengeRuntimeForSplitTest(t, keys)

	got, err := rt.buildAndObfuscateDynamicModule(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, got)

	epoch, signKey := keys.Current()
	keyHex := hex.EncodeToString(signKey)

	// The hook sentinel must appear (reservedStrings keeps it intact).
	assert.Contains(t, got, hookSentinel,
		"dynamic module is missing the hook sentinel %q", hookSentinel)

	// The key MUST NOT appear in plain hex form. The obfuscator's
	// string-array transform should have encoded it. If the literal hex
	// shows up the obfuscation strength has dropped, defeating the whole
	// point of the split-bundle design.
	assert.NotContains(t, got, keyHex,
		"per-epoch key leaked into the dynamic module in plain hex (obfuscator regression?)")

	// Sanity: epoch number can leak as a literal — it's not a secret.
	t.Logf("dynamic module size for epoch %d: %d bytes", epoch, len(got))
}

// TestSplitBundle_DynamicModuleCachedPerEpoch confirms repeated calls in
// the same epoch share the obfuscation cost (single-flight via cache).
//
// We pin the keyring's clock so the two calls are guaranteed to see the
// same epoch — without this, the ~12s obfuscation cost can straddle a
// rotation boundary on testKeyRing's 1-minute interval and the second
// call ends up generating a different module under a different key.
func TestSplitBundle_DynamicModuleCachedPerEpoch(t *testing.T) {
	keys := testKeyRing()
	pinned := time.Now()
	keys.now = func() time.Time { return pinned }

	rt := newChallengeRuntimeForSplitTest(t, keys)

	first, err := rt.buildAndObfuscateDynamicModule(context.Background())
	require.NoError(t, err)

	second, err := rt.buildAndObfuscateDynamicModule(context.Background())
	require.NoError(t, err)

	assert.Equal(t, first, second, "second call must return the cached module byte-for-byte")
}

// TestSplitBundle_DynamicModuleRebuildsOnEpochAdvance asserts that when the
// keyring rolls to a new epoch, buildAndObfuscateDynamicModule produces a
// fresh module embedding the new key.
func TestSplitBundle_DynamicModuleRebuildsOnEpochAdvance(t *testing.T) {
	keys := testKeyRing()
	rt := newChallengeRuntimeForSplitTest(t, keys)

	first, err := rt.buildAndObfuscateDynamicModule(context.Background())
	require.NoError(t, err)
	firstEpoch, _ := keys.Current()

	// Advance the keyring's clock past the rotation interval.
	keys.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	second, err := rt.buildAndObfuscateDynamicModule(context.Background())
	require.NoError(t, err)
	secondEpoch, _ := keys.Current()

	assert.NotEqual(t, firstEpoch, secondEpoch, "epoch did not advance")
	assert.NotEqual(t, first, second, "dynamic module did not change after epoch advance")
}

// TestSplitBundle_DynamicModuleConcurrentSingleflight is a regression
// guard for the broken-pipe-at-rotation bug. N concurrent goroutines call
// buildAndObfuscateDynamicModule for the same epoch; only ONE must
// actually run the obfuscator (the others share its result via
// singleflight). If we ever hold the cache mutex across the obfuscation
// pass again, this test will time out OR show every caller doing its
// own obfuscation.
func TestSplitBundle_DynamicModuleConcurrentSingleflight(t *testing.T) {
	keys := testKeyRing()
	pinned := time.Now()
	keys.now = func() time.Time { return pinned }
	rt := newChallengeRuntimeForSplitTest(t, keys)

	const N = 8
	results := make([]string, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(N)

	start := time.Now()
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			out, err := rt.buildAndObfuscateDynamicModule(context.Background())
			results[idx] = out
			errs[idx] = err
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}

	// All callers must have observed the same obfuscation output. If any
	// caller diverged, singleflight wasn't doing its job.
	for i := 1; i < N; i++ {
		require.Equal(t, results[0], results[i],
			"goroutines %d and 0 saw different module bytes; singleflight is broken", i)
	}

	// Tighter bound: with N=8 goroutines and a single ~5s obfuscation,
	// the wall-clock should be roughly one obfuscation, not N. We use
	// 2x as the threshold to absorb scheduler noise; a regression where
	// every caller runs its own obfuscation would push elapsed past
	// N * 5s = 40s, way above the threshold.
	t.Logf("8 concurrent buildAndObfuscateDynamicModule calls completed in %s", elapsed)
	require.Less(t, elapsed, 15*time.Second,
		"concurrent calls took %s; singleflight likely not coalescing (would expect 1 obfuscation, got serial)",
		elapsed)
}

// TestSplitBundle_HTMLDoesNotContainSecret is the most important security
// regression guard for MVP-4: the HTML challenge page MUST NOT contain the
// per-epoch sign key in plain (hex) form. If it does, an attacker can
// scrape it and forge tickets without running the obfuscated bundle —
// exactly the failure mode the split-bundle protocol was designed to fix.
func TestSplitBundle_HTMLDoesNotContainSecret(t *testing.T) {
	keys := testKeyRing()
	rt := newChallengeRuntimeForSplitTest(t, keys)

	html, err := rt.GetChallengePage("test-agent", 8)
	require.NoError(t, err)
	require.NotEmpty(t, html)

	_, signKey := keys.Current()
	keyHex := hex.EncodeToString(signKey)

	assert.NotContains(t, html, keyHex,
		"the per-epoch sign key leaked into plain HTML \u2014 split-bundle invariant violated")
}

// hookSentinel must match the constant used by both challenge.js (as
// CSEC_HOOK_NAME) and obfuscate.js (in reservedStrings). Hardcoded here on
// purpose so the test breaks if the JS-side constant is renamed without a
// matching update.
const hookSentinel = "__CSEC_CHALLENGE_HOOK_v1__"

// newChallengeRuntimeForSplitTest builds a runtime with WASM + the baked-in
// initial bundle but a deterministic keyring, so split-bundle assertions
// can be made against a known key.
func newChallengeRuntimeForSplitTest(t *testing.T, keys *KeyRing) *ChallengeRuntime {
	t.Helper()
	rt, err := NewChallengeRuntime(context.Background(),
		WithMasterSecret(testSecret),
	)
	require.NoError(t, err)
	rt.keys = keys
	// Reset the dynamic module cache because the constructor pre-warmed it
	// with rt.keys (which we just swapped). The next call regenerates.
	rt.dynamicModuleCacheMu.Lock()
	rt.dynamicModuleCache = make(map[int64]string)
	rt.dynamicModuleCacheMu.Unlock()
	return rt
}
