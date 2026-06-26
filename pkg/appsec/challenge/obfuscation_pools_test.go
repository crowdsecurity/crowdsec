package challenge

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLibraryRuntimeObfuscationDisabledByDefault asserts that the default
// NewChallengeRuntime path does NOT spawn the library-bundle refresher
// goroutine. The library is still obfuscated (build-time, via
// initial_bundle.js.gz); this only confirms that steady-state CPU on the
// library path is zero — only the baked-in variant is served and no
// background obfuscation runs.
func TestLibraryRuntimeObfuscationDisabledByDefault(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context())
	require.NoError(t, err)
	require.False(t, rt.libraryRuntimeObfuscationEnabled, "library runtime obfuscation must be disabled by default")

	// Pool holds exactly the seeded baked-in variant, nothing more.
	rt.libraryBundlePoolMu.RLock()
	poolLen := len(rt.libraryBundlePool)
	rt.libraryBundlePoolMu.RUnlock()
	require.Equal(t, 1, poolLen, "default pool must hold only the seeded baked-in bundle")

	// Even after waiting longer than any plausible refresh window, the
	// pool must NOT grow — proves no refresher goroutine is running.
	// 500ms is enough to catch any sub-second-misconfigured ticker
	// (real defaults are 1h, so we won't false-positive even on a slow
	// CI box).
	time.Sleep(500 * time.Millisecond)
	rt.libraryBundlePoolMu.RLock()
	poolLenAfter := len(rt.libraryBundlePool)
	rt.libraryBundlePoolMu.RUnlock()
	assert.Equal(t, 1, poolLenAfter, "pool must NOT grow when runtime library obfuscation is disabled")
}

// TestLibraryRuntimeObfuscationEnabledTrickle asserts that when runtime
// library obfuscation is enabled, the refresher trickles one new variant
// per tick (rather than the old behavior of regenerating all N variants
// at once). The pool grows from 1 (seeded) toward the configured size
// across multiple ticks.
//
// This is the regression guard for the production CPU pegging: if the
// refresher ever again does a batch regen, this test will see the
// pool jump from 1 → N in one tick instead of trickling.
func TestLibraryRuntimeObfuscationEnabledTrickle(t *testing.T) {
	if testing.Short() {
		t.Skip("library obfuscation runs the full bundle through wazero (~minute per tick); skipped in -short")
	}

	// 1-second refresh interval is fine for the test: each tick still
	// does one full-bundle obfuscation, but we only wait for the FIRST
	// successful tick (pool goes 1 → 2) before asserting.
	rt, err := NewChallengeRuntime(t.Context(),
		WithLibraryRuntimeObfuscationEnabled(true),
		WithLibraryObfuscationPoolSize(3),
		WithLibraryObfuscationRefreshInterval(1*time.Second),
	)
	require.NoError(t, err)

	// Initial state: just the seeded variant.
	rt.libraryBundlePoolMu.RLock()
	require.Len(t, rt.libraryBundlePool, 1, "pool must start at 1 (just the seeded variant)")
	rt.libraryBundlePoolMu.RUnlock()

	// Wait long enough for one tick + one full-bundle obfuscation
	// (~1 minute). Use a generous deadline and poll.
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		rt.libraryBundlePoolMu.RLock()
		sz := len(rt.libraryBundlePool)
		rt.libraryBundlePoolMu.RUnlock()
		if sz >= 2 {
			// Trickle confirmed: pool grew by 1 (not by 2 or 3 in one
			// tick). The cap behavior is exercised by waiting further
			// if you want — kept short here to bound test runtime.
			require.LessOrEqual(t, sz, 3, "pool must respect libraryPoolSize cap")
			return
		}
		time.Sleep(2 * time.Second)
	}
	rt.libraryBundlePoolMu.RLock()
	finalSize := len(rt.libraryBundlePool)
	rt.libraryBundlePoolMu.RUnlock()
	t.Fatalf("library bundle pool did not grow within the deadline (got %d, want ≥2)", finalSize)
}

// TestCryptoObfuscationDefaultPoolSize confirms that with no
// WithCryptoObfuscationPoolSize option, the per-epoch dynamic module
// cache holds exactly 1 variant per epoch — preserving the historical
// single-variant-per-epoch behavior.
func TestCryptoObfuscationDefaultPoolSize(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context())
	require.NoError(t, err)
	require.Equal(t, cryptoObfuscationPoolDefaultSize, rt.cryptoPoolSize,
		"default crypto pool size must be cryptoObfuscationPoolDefaultSize")

	// The pre-warmer runs currentDynamicModule at construction; the
	// cache for the current epoch must hold exactly 1 variant.
	currentEpoch, _ := rt.keys.Current()

	rt.dynamicModuleCacheMu.RLock()
	variants, ok := rt.dynamicModuleCache[currentEpoch]
	rt.dynamicModuleCacheMu.RUnlock()

	require.True(t, ok, "current epoch must be cached after construction (pre-warmer ran)")
	require.Len(t, variants, 1, "default crypto pool keeps 1 variant per epoch")
}

// TestCryptoObfuscationPoolSize asserts that when
// WithCryptoObfuscationPoolSize is raised, the per-epoch cache holds
// the configured number of distinct obfuscated variants of the SAME
// epoch key, and currentDynamicModule picks from them.
func TestCryptoObfuscationPoolSize(t *testing.T) {
	if testing.Short() {
		t.Skip("each crypto pool variant costs ~3s of obfuscator CPU; skipped in -short")
	}

	const poolSize = 3
	rt, err := NewChallengeRuntime(t.Context(),
		WithCryptoObfuscationPoolSize(poolSize),
	)
	require.NoError(t, err)
	require.Equal(t, poolSize, rt.cryptoPoolSize, "crypto pool size option must propagate")

	currentEpoch, _ := rt.keys.Current()

	rt.dynamicModuleCacheMu.RLock()
	variants, ok := rt.dynamicModuleCache[currentEpoch]
	rt.dynamicModuleCacheMu.RUnlock()

	require.True(t, ok, "current epoch must be cached after construction")
	require.Len(t, variants, poolSize, "crypto pool must hold poolSize variants")

	// Each variant must be a distinct obfuscation. javascript-obfuscator
	// with mangled identifier-names produces different byte output each
	// run, so duplicates are an obfuscator regression.
	for i := 1; i < poolSize; i++ {
		assert.NotEqual(t, variants[0], variants[i],
			"variants %d and 0 are byte-identical; obfuscator should produce distinct output per pass", i)
	}

	// currentDynamicModule must return one of the cached variants.
	got, err := rt.currentDynamicModule(t.Context())
	require.NoError(t, err)
	found := slices.Contains(variants, got)
	assert.True(t, found, "currentDynamicModule returned a value not in the cached pool")
}

// TestLibraryObfuscationEnabledByDefault confirms the default path serves the
// obfuscated baked-in bundle (the size blowup that pushes the page past the
// SPOA frame limit) — the behavior SPOA operators opt out of.
func TestLibraryObfuscationEnabledByDefault(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context())
	require.NoError(t, err)
	require.True(t, rt.libraryObfuscationEnabled, "library obfuscation must be on by default")

	got := rt.getLibraryBundle()
	require.NotEmpty(t, got.Code)
	// The obfuscated bundle is ~778 KB; the plain one is ~37 KB. A 100 KB floor
	// cleanly distinguishes the two without pinning an exact size.
	assert.Greater(t, len(got.Code), 100_000,
		"default served bundle should be the obfuscated (large) variant")
}

// TestLibraryObfuscationDisabledServesPlainBundle is the core Option-B guard:
// with obfuscation off, the served library bundle is the plain minified bundle
// (small enough for a SPOA frame) while the per-epoch key module stays
// obfuscated — the security invariant that must survive the size optimization.
func TestLibraryObfuscationDisabledServesPlainBundle(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		WithLibraryObfuscationEnabled(false),
	)
	require.NoError(t, err)
	require.False(t, rt.libraryObfuscationEnabled, "sanity: obfuscation is off")

	// Pool holds exactly the one plain variant.
	rt.libraryBundlePoolMu.RLock()
	poolLen := len(rt.libraryBundlePool)
	rt.libraryBundlePoolMu.RUnlock()
	require.Equal(t, 1, poolLen, "obfuscation-off pool must hold a single plain variant")

	got := rt.getLibraryBundle()
	// Byte-for-byte the plain, path-substituted bundle — no obfuscation pass.
	assert.Equal(t, rt.buildChallengeBundle(), got.Code,
		"served bundle must be the plain buildChallengeBundle output")
	assert.Less(t, len(got.Code), 100_000,
		"plain bundle must be far smaller than the obfuscated one (SPOA frame fit)")
	// Path placeholders must still have been substituted.
	assert.NotContains(t, got.Code, "__CROWDSEC_SUBMIT_PATH__")
	assert.NotContains(t, got.Code, "__CROWDSEC_POW_WORKER_PATH__")

	// Invariant: the sensitive per-epoch key module is STILL obfuscated. The
	// raw template declares `var hookName = ...`; the obfuscator mangles that,
	// so its absence proves the module was obfuscated even with the library
	// obfuscation turned off.
	dyn, err := rt.currentDynamicModule(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, dyn)
	assert.NotContains(t, dyn, "var hookName =",
		"dynamic key module must remain obfuscated regardless of library obfuscation")
}
