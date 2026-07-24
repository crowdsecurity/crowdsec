package challenge

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChallengeCodeSeededStatically asserts that the default
// NewChallengeRuntime path loads the build-time-obfuscated challenge code
// once from initial_bundle.js.gz and serves it verbatim — there is no
// runtime re-obfuscation or pool for the (public) library path anymore.
func TestChallengeCodeSeededStatically(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context())
	require.NoError(t, err)

	code := rt.getChallengeCode()
	require.NotEmpty(t, code, "challenge code must be seeded from the baked-in initial bundle")

	// The hook sentinel must survive obfuscation so the dynamic key module
	// can find the registered hook (reservedStrings in obfuscate.js).
	require.Contains(t, code, hookSentinel,
		"obfuscated challenge code must preserve the hook sentinel verbatim")

	// The accessor is a stable read of static state: repeated calls return
	// the identical string (no pool, no random selection).
	assert.Equal(t, code, rt.getChallengeCode(), "challenge code must be static across calls")
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

	// The pre-warmer runs currentDynamicModule at construction, so at least
	// one epoch must be cached. We assert on the cache contents rather than
	// re-reading the clock: obfuscation spans several seconds, so a 5m
	// rotation boundary can cross during construction and advance the current
	// epoch away from the one that was warmed. Whatever epochs are cached, the
	// default pool must hold exactly 1 variant each.
	rt.dynamicModuleCacheMu.RLock()
	defer rt.dynamicModuleCacheMu.RUnlock()

	require.NotEmpty(t, rt.dynamicModuleCache, "pre-warmer must cache at least the current epoch")
	for epoch, variants := range rt.dynamicModuleCache {
		require.Lenf(t, variants, 1, "default crypto pool keeps 1 variant per epoch (epoch %d)", epoch)
	}
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
