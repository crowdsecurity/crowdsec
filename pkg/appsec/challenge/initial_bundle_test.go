package challenge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewChallengeRuntimeStartupBudget ensures NewChallengeRuntime returns
// quickly (seeded from the baked-in bundle), without paying the ~1 minute of
// synchronous obfuscation it used to.
func TestNewChallengeRuntimeStartupBudget(t *testing.T) {
	const budget = 10 * time.Second

	start := time.Now()
	rt, err := NewChallengeRuntime(t.Context())
	dur := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, rt)
	t.Logf("NewChallengeRuntime returned in %s", dur)

	if dur > budget {
		t.Fatalf("NewChallengeRuntime took %s, exceeds budget of %s; baked-in initial bundle should make this near-instant", dur, budget)
	}

	// The pool must hold at least the seeded bundle so the very first request
	// can be served.
	got := rt.getLibraryBundle()
	require.NotEmpty(t, got.Code, "pool should be seeded with the baked-in initial bundle")
}

// TestSeedCacheFromInitialBundle directly exercises the seeding helper and
// asserts the bundle decompresses to non-empty obfuscated JS.
func TestSeedCacheFromInitialBundle(t *testing.T) {
	rt := &ChallengeRuntime{
		libraryBundlePool: make([]obfuscatedScript, 0, libraryBundlePoolDefaultSize),
		libraryPoolSize:   libraryBundlePoolDefaultSize,
	}

	require.NoError(t, rt.seedCacheFromInitialBundle())

	rt.libraryBundlePoolMu.RLock()
	defer rt.libraryBundlePoolMu.RUnlock()
	require.Len(t, rt.libraryBundlePool, 1)
	require.NotEmpty(t, rt.libraryBundlePool[0].Code)

	// Sanity check: the obfuscated output should be much larger than the
	// source bundle (high-obfuscation roughly 20x inflation observed in the
	// feasibility benchmark).
	t.Logf("seeded variant size: %d bytes", len(rt.libraryBundlePool[0].Code))
	require.Greater(t, len(rt.libraryBundlePool[0].Code), 100_000,
		"seeded bundle is suspiciously small; was it actually obfuscated?")

	// The placeholders that the source bundle uses for path substitution must
	// have been replaced before obfuscation (their literal form should not
	// remain in the output).
	require.NotContains(t, rt.libraryBundlePool[0].Code, "__CROWDSEC_SUBMIT_PATH__",
		"submit path placeholder still present; substitution missed at build time")
	require.NotContains(t, rt.libraryBundlePool[0].Code, "__CROWDSEC_POW_WORKER_PATH__",
		"pow worker path placeholder still present; substitution missed at build time")
}
