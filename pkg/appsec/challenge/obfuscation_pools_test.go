package challenge

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChallengeCodeSeededStatically asserts that the default
// NewChallengeRuntime path loads the build-time-obfuscated challenge code
// once from initial_bundle.js.gz and serves it verbatim — there is no
// runtime re-obfuscation or pool for the (public) library path anymore.
func TestChallengeCodeSeededStatically(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(), withoutPreWarm())
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

// TestCryptoObfuscationPoolSize asserts the per-epoch cache holds exactly
// cryptoPoolSize distinct obfuscated variants of the same epoch key, and
// that currentDynamicModule picks from them.
//
// The keyring clock is pinned and the runtime built withoutPreWarm: a
// variant costs ~4s, so an unpinned pool of N can straddle a 5m rotation
// boundary and move the current epoch out from under the assertions.
func TestCryptoObfuscationPoolSize(t *testing.T) {
	tests := []struct {
		name     string
		opts     []Option
		wantPool int
	}{
		{
			name:     "default",
			wantPool: cryptoObfuscationPoolDefaultSize,
		},
		{
			name:     "explicit pool of 3",
			opts:     []Option{WithCryptoObfuscationPoolSize(3)},
			wantPool: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPool > 1 && testing.Short() {
				t.Skip("each extra crypto pool variant costs ~4s of obfuscator CPU; skipped in -short")
			}

			rt, err := NewChallengeRuntime(t.Context(), append(tc.opts, withoutPreWarm())...)
			require.NoError(t, err)
			require.Equal(t, tc.wantPool, rt.cryptoPoolSize, "crypto pool size option must propagate")

			pinned := time.Now()
			rt.keys.now = func() time.Time { return pinned }

			epoch, _ := rt.keys.Current()
			variants, err := rt.dynamicModuleForEpoch(t.Context(), epoch)
			require.NoError(t, err)
			require.Len(t, variants, tc.wantPool, "crypto pool must hold cryptoPoolSize variants")

			// Identical variants would make the pool wasted CPU.
			for i := 1; i < tc.wantPool; i++ {
				assert.NotEqual(t, variants[0], variants[i],
					"variants %d and 0 are byte-identical; obfuscator should produce distinct output per pass", i)
			}

			got, err := rt.currentDynamicModule(t.Context())
			require.NoError(t, err)
			assert.True(t, slices.Contains(variants, got),
				"currentDynamicModule returned a value not in the cached pool")
		})
	}
}
