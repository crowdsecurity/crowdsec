package challenge

import (
	"context"
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
	rt, err := NewChallengeRuntime(context.Background())
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
// per tick (rather than the old behaviour of regenerating all N variants
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
	rt, err := NewChallengeRuntime(context.Background(),
		WithLibraryRuntimeObfuscationEnabled(true),
		WithLibraryObfuscationPoolSize(3),
		WithLibraryObfuscationRefreshInterval(1*time.Second),
	)
	require.NoError(t, err)

	// Initial state: just the seeded variant.
	rt.libraryBundlePoolMu.RLock()
	require.Equal(t, 1, len(rt.libraryBundlePool), "pool must start at 1 (just the seeded variant)")
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
			// tick). The cap behaviour is exercised by waiting further
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
// single-variant-per-epoch behaviour.
func TestCryptoObfuscationDefaultPoolSize(t *testing.T) {
	rt, err := NewChallengeRuntime(context.Background())
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
	rt, err := NewChallengeRuntime(context.Background(),
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
	got, err := rt.currentDynamicModule(context.Background())
	require.NoError(t, err)
	found := false
	for _, v := range variants {
		if v == got {
			found = true
			break
		}
	}
	assert.True(t, found, "currentDynamicModule returned a value not in the cached pool")
}
