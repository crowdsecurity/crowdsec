package challenge

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigMergeFromNilReceiverAndOther covers the two no-op edge cases:
// merging into a nil receiver and merging a nil source. Both must not panic
// and must not change anything.
func TestConfigMergeFromNilReceiverAndOther(t *testing.T) {
	var nilCfg *Config
	require.NotPanics(t, func() { nilCfg.MergeFrom(&Config{CookieTTL: new(time.Hour)}) })

	dst := &Config{CookieTTL: new(time.Hour)}
	dst.MergeFrom(nil)
	require.NotNil(t, dst.CookieTTL)
	assert.Equal(t, time.Hour, *dst.CookieTTL, "nil source must leave existing fields untouched")
}

// TestConfigMergeFromOverlaysOnlyNonNilFields confirms the per-field "last
// wins" semantics: each set field in `other` overrides `c`, but unset fields
// leave `c`'s existing values intact. This is what lets multiple appsec-
// configs each contribute a disjoint subset without one wiping the others.
func TestConfigMergeFromOverlaysOnlyNonNilFields(t *testing.T) {
	dst := &Config{
		MasterSecret:              new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		KeyRotationInterval:       new(5 * time.Minute),
		MaxLiveEpochs:             new(3),
		CookieTTL:                 new(12 * time.Hour),
		CryptoObfuscationPoolSize: new(1),
	}

	src := &Config{
		// Override CookieTTL and CryptoObfuscationPoolSize; leave others
		// nil so the dst values must survive.
		CookieTTL:                 new(1 * time.Hour),
		CryptoObfuscationPoolSize: new(4),
		// New fields not present on dst.
		LibraryRuntimeObfuscationEnabled:  new(true),
		LibraryObfuscationPoolSize:        new(2),
		LibraryObfuscationRefreshInterval: new(30 * time.Minute),
		SpentSetMaxEntries:                new(500_000),
	}

	dst.MergeFrom(src)

	// Overridden fields take src values.
	assert.Equal(t, 1*time.Hour, *dst.CookieTTL)
	assert.Equal(t, 4, *dst.CryptoObfuscationPoolSize)

	// Untouched-by-src fields keep dst values.
	require.NotNil(t, dst.MasterSecret)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", *dst.MasterSecret)
	assert.Equal(t, 5*time.Minute, *dst.KeyRotationInterval)
	assert.Equal(t, 3, *dst.MaxLiveEpochs)

	// New-from-src fields appear on dst.
	require.NotNil(t, dst.LibraryRuntimeObfuscationEnabled)
	assert.True(t, *dst.LibraryRuntimeObfuscationEnabled)
	assert.Equal(t, 2, *dst.LibraryObfuscationPoolSize)
	assert.Equal(t, 30*time.Minute, *dst.LibraryObfuscationRefreshInterval)
	assert.Equal(t, 500_000, *dst.SpentSetMaxEntries)
}

// TestBuildOptionsNilOrEmptyConfig confirms a nil or fully-empty Config emits
// only the always-present component-logger option; the runtime is otherwise
// constructed with its built-in defaults.
func TestBuildOptionsNilOrEmptyConfig(t *testing.T) {
	opts, err := BuildOptions(nil, nil)
	require.NoError(t, err)
	assert.Len(t, opts, 1, "nil config still emits the component-logger option")

	opts, err = BuildOptions(&Config{}, nil)
	require.NoError(t, err)
	assert.Len(t, opts, 1, "empty config still emits the component-logger option")
}

// TestBuildOptionsTranslatesFieldsToRuntimeBehavior wires a populated Config
// through BuildOptions and NewChallengeRuntime, then asserts the runtime's
// observable fields match the configured values. This is the integration
// guard for "appsec-config values reach the running challenge engine".
func TestBuildOptionsTranslatesFieldsToRuntimeBehavior(t *testing.T) {
	cfg := &Config{
		MasterSecret:                      new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		KeyRotationInterval:               new(3 * time.Minute),
		MaxLiveEpochs:                     new(4),
		CookieTTL:                         new(2 * time.Hour),
		CryptoObfuscationPoolSize:         new(2),
		LibraryRuntimeObfuscationEnabled:  new(true),
		LibraryObfuscationPoolSize:        new(2),
		LibraryObfuscationRefreshInterval: new(45 * time.Minute),
		SpentSetMaxEntries:                new(250_000),
	}

	opts, err := BuildOptions(cfg, nil)
	require.NoError(t, err)
	require.Len(t, opts, 10, "every populated field + the component logger must emit an option")

	rt, err := NewChallengeRuntime(t.Context(), opts...)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Hour, rt.cookieTTL, "CookieTTL must reach the runtime")
	assert.Equal(t, 2, rt.cryptoPoolSize, "CryptoObfuscationPoolSize must reach the runtime")
	assert.True(t, rt.libraryRuntimeObfuscationEnabled, "LibraryRuntimeObfuscationEnabled must reach the runtime")
	assert.Equal(t, 2, rt.libraryPoolSize, "LibraryObfuscationPoolSize must reach the runtime")
	assert.Equal(t, 45*time.Minute, rt.libraryRefreshInterval, "LibraryObfuscationRefreshInterval must reach the runtime")
	assert.Equal(t, 250_000, rt.spent.maxEntries, "SpentSetMaxEntries must reach the runtime")
}

// TestLibraryPoolSizeClampedWhenRuntimeObfuscationDisabled confirms the
// runtime silently clamps libraryPoolSize to 1 when runtime obfuscation
// is off. The pool's only source in that mode is the baked-in initial
// bundle, so a larger ceiling would leave empty slots forever; clamping
// avoids ambiguity in metrics and reflects reality.
func TestLibraryPoolSizeClampedWhenRuntimeObfuscationDisabled(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		// Runtime obfuscation deliberately NOT enabled.
		WithLibraryObfuscationPoolSize(5),
	)
	require.NoError(t, err)

	assert.False(t, rt.libraryRuntimeObfuscationEnabled,
		"sanity: runtime obfuscation is off")
	assert.Equal(t, 1, rt.libraryPoolSize,
		"libraryPoolSize must be clamped to 1 when runtime obfuscation is off")

	// And the actual pool contents reflect that — just the seeded variant.
	rt.libraryBundlePoolMu.RLock()
	poolLen := len(rt.libraryBundlePool)
	rt.libraryBundlePoolMu.RUnlock()
	assert.Equal(t, 1, poolLen, "pool must hold only the baked-in initial bundle")
}

// TestLibraryPoolSizeHonoredWhenRuntimeObfuscationEnabled confirms the
// clamp does NOT fire when runtime obfuscation is enabled — the
// configured pool size must propagate as-is so the refresher has room
// to grow into.
func TestLibraryPoolSizeHonoredWhenRuntimeObfuscationEnabled(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		WithLibraryRuntimeObfuscationEnabled(true),
		WithLibraryObfuscationPoolSize(3),
	)
	require.NoError(t, err)

	assert.True(t, rt.libraryRuntimeObfuscationEnabled)
	assert.Equal(t, 3, rt.libraryPoolSize,
		"libraryPoolSize must be honored when runtime obfuscation is on")
}

// TestBuildOptionsInvalidMasterSecret confirms a malformed master_secret
// surfaces as a configuration error rather than silently falling back to a
// random secret — that would be a footgun in distributed deployments.
func TestBuildOptionsInvalidMasterSecret(t *testing.T) {
	cfg := &Config{
		MasterSecret: new("too-short"),
	}
	_, err := BuildOptions(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "master_secret")
}

// TestSealAllowlistCookieTTLOverride exercises the per-call TTL plumbing on
// SealAllowlistCookie: when ttlOverride is non-nil and positive, the
// generated cookie's Max-Age reflects the override rather than the
// runtime-global cookie_ttl. Nil falls back to the runtime default.
func TestSealAllowlistCookieTTLOverride(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		WithMasterSecret([]byte("0123456789abcdef0123456789abcdef")),
		WithCookieTTL(12*time.Hour),
	)
	require.NoError(t, err)

	req := &http.Request{
		Header: http.Header{"User-Agent": []string{"test-agent"}},
		URL:    mustURL("https://example.test/protected"),
	}

	// Override → short TTL.
	override := 30 * time.Minute
	before := time.Now().Unix()
	ck, err := rt.SealAllowlistCookie(req, "explicit-short", &override)
	require.NoError(t, err)
	require.NotNil(t, ck)
	assert.InDelta(t, before+int64(override.Seconds()), ck.Expiration, 2,
		"override TTL must drive the cookie expiration")

	// No override → runtime default (12h).
	before = time.Now().Unix()
	ck, err = rt.SealAllowlistCookie(req, "fallback", nil)
	require.NoError(t, err)
	require.NotNil(t, ck)
	assert.InDelta(t, before+int64((12*time.Hour).Seconds()), ck.Expiration, 2,
		"nil override must fall back to runtime cookie_ttl")

	// Zero/negative override → treated as "no override", uses runtime default.
	before = time.Now().Unix()
	zero := time.Duration(0)
	ck, err = rt.SealAllowlistCookie(req, "zero-fallback", &zero)
	require.NoError(t, err)
	require.NotNil(t, ck)
	assert.InDelta(t, before+int64((12*time.Hour).Seconds()), ck.Expiration, 2,
		"non-positive override must fall back to runtime cookie_ttl")
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
