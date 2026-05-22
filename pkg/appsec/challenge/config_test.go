package challenge

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrStr(s string) *string             { return &s }
func ptrInt(i int) *int                   { return &i }
func ptrBool(b bool) *bool                { return &b }
func ptrDur(d time.Duration) *time.Duration { return &d }

// TestConfigMergeFromNilReceiverAndOther covers the two no-op edge cases:
// merging into a nil receiver and merging a nil source. Both must not panic
// and must not change anything.
func TestConfigMergeFromNilReceiverAndOther(t *testing.T) {
	var nilCfg *Config
	require.NotPanics(t, func() { nilCfg.MergeFrom(&Config{CookieTTL: ptrDur(time.Hour)}) })

	dst := &Config{CookieTTL: ptrDur(time.Hour)}
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
		MasterSecret:              ptrStr("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		KeyRotationInterval:       ptrDur(5 * time.Minute),
		MaxLiveEpochs:             ptrInt(3),
		CookieTTL:                 ptrDur(12 * time.Hour),
		CryptoObfuscationPoolSize: ptrInt(1),
	}

	src := &Config{
		// Override CookieTTL and CryptoObfuscationPoolSize; leave others
		// nil so the dst values must survive.
		CookieTTL:                 ptrDur(1 * time.Hour),
		CryptoObfuscationPoolSize: ptrInt(4),
		// New fields not present on dst.
		LibraryRuntimeObfuscationEnabled:  ptrBool(true),
		LibraryObfuscationPoolSize:        ptrInt(2),
		LibraryObfuscationRefreshInterval: ptrDur(30 * time.Minute),
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
}

// TestBuildOptionsNilOrEmptyConfig confirms a nil or fully-empty Config
// produces no Options; the runtime is then constructed with its built-in
// defaults.
func TestBuildOptionsNilOrEmptyConfig(t *testing.T) {
	opts, err := BuildOptions(nil)
	require.NoError(t, err)
	assert.Empty(t, opts)

	opts, err = BuildOptions(&Config{})
	require.NoError(t, err)
	assert.Empty(t, opts)
}

// TestBuildOptionsTranslatesFieldsToRuntimeBehavior wires a populated Config
// through BuildOptions and NewChallengeRuntime, then asserts the runtime's
// observable fields match the configured values. This is the integration
// guard for "appsec-config values reach the running challenge engine".
func TestBuildOptionsTranslatesFieldsToRuntimeBehavior(t *testing.T) {
	cfg := &Config{
		MasterSecret:                      ptrStr("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		KeyRotationInterval:               ptrDur(3 * time.Minute),
		MaxLiveEpochs:                     ptrInt(4),
		CookieTTL:                         ptrDur(2 * time.Hour),
		CryptoObfuscationPoolSize:         ptrInt(2),
		LibraryRuntimeObfuscationEnabled:  ptrBool(true),
		LibraryObfuscationPoolSize:        ptrInt(2),
		LibraryObfuscationRefreshInterval: ptrDur(45 * time.Minute),
	}

	opts, err := BuildOptions(cfg)
	require.NoError(t, err)
	require.Len(t, opts, 8, "every populated field must emit an option")

	rt, err := NewChallengeRuntime(context.Background(), opts...)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Hour, rt.cookieTTL, "CookieTTL must reach the runtime")
	assert.Equal(t, 2, rt.cryptoPoolSize, "CryptoObfuscationPoolSize must reach the runtime")
	assert.True(t, rt.libraryRuntimeObfuscationEnabled, "LibraryRuntimeObfuscationEnabled must reach the runtime")
	assert.Equal(t, 2, rt.libraryPoolSize, "LibraryObfuscationPoolSize must reach the runtime")
	assert.Equal(t, 45*time.Minute, rt.libraryRefreshInterval, "LibraryObfuscationRefreshInterval must reach the runtime")
}

// TestLibraryPoolSizeClampedWhenRuntimeObfuscationDisabled confirms the
// runtime silently clamps libraryPoolSize to 1 when runtime obfuscation
// is off. The pool's only source in that mode is the baked-in initial
// bundle, so a larger ceiling would leave empty slots forever; clamping
// avoids ambiguity in metrics and reflects reality.
func TestLibraryPoolSizeClampedWhenRuntimeObfuscationDisabled(t *testing.T) {
	rt, err := NewChallengeRuntime(context.Background(),
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
	rt, err := NewChallengeRuntime(context.Background(),
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
		MasterSecret: ptrStr("too-short"),
	}
	_, err := BuildOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "master_secret")
}

// TestSealAllowlistCookieTTLOverride exercises the per-call TTL plumbing on
// SealAllowlistCookie: when ttlOverride is non-nil and positive, the
// generated cookie's Max-Age reflects the override rather than the
// runtime-global cookie_ttl. Nil falls back to the runtime default.
func TestSealAllowlistCookieTTLOverride(t *testing.T) {
	rt, err := NewChallengeRuntime(context.Background(),
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
