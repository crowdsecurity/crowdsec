package challenge

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
		SpentSetMaxEntries: new(500_000),
		MaxCookieSize:      new(8192),
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
	require.NotNil(t, dst.SpentSetMaxEntries)
	assert.Equal(t, 500_000, *dst.SpentSetMaxEntries)
	assert.Equal(t, 8192, *dst.MaxCookieSize)
}

// TestBuildOptionsNilOrEmptyConfig confirms a nil or fully-empty Config emits
// only the always-present component-logger option; the runtime is otherwise
// constructed with its built-in defaults.
func TestBuildOptionsNilOrEmptyConfig(t *testing.T) {
	opts, err := BuildOptions(nil, nil, "")
	require.NoError(t, err)
	assert.Len(t, opts, 1, "nil config still emits the component-logger option")

	opts, err = BuildOptions(&Config{}, nil, "")
	require.NoError(t, err)
	assert.Len(t, opts, 1, "empty config still emits the component-logger option")
}

// TestBuildOptionsTranslatesFieldsToRuntimeBehavior wires a populated Config
// through BuildOptions and NewChallengeRuntime, then asserts the runtime's
// observable fields match the configured values. This is the integration
// guard for "appsec-config values reach the running challenge engine".
func TestBuildOptionsTranslatesFieldsToRuntimeBehavior(t *testing.T) {
	cfg := &Config{
		MasterSecret:              new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		KeyRotationInterval:       new(3 * time.Minute),
		MaxLiveEpochs:             new(4),
		CookieTTL:                 new(2 * time.Hour),
		CryptoObfuscationPoolSize: new(2),
		SpentSetMaxEntries:        new(250_000),
		MaxCookieSize:             new(8192),
	}

	opts, err := BuildOptions(cfg, nil, "")
	require.NoError(t, err)
	require.Len(t, opts, 8, "every populated field + the component logger must emit an option")

	// withoutPreWarm: this only reads config-derived fields, it never serves
	// a page.
	rt, err := NewChallengeRuntime(t.Context(), append(opts, withoutPreWarm())...)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Hour, rt.cookieTTL, "CookieTTL must reach the runtime")
	assert.Equal(t, 2, rt.cryptoPoolSize, "CryptoObfuscationPoolSize must reach the runtime")
	assert.Equal(t, 250_000, rt.spent.maxEntries, "SpentSetMaxEntries must reach the runtime")
	assert.Equal(t, 8192, rt.maxCookieLen, "MaxCookieSize must reach the runtime")
}

// TestBuildOptionsInvalidMasterSecret confirms a malformed master_secret
// surfaces as a configuration error rather than silently falling back to a
// random secret — that would be a footgun in distributed deployments.
func TestBuildOptionsInvalidMasterSecret(t *testing.T) {
	cfg := &Config{
		MasterSecret: new("too-short"),
	}
	_, err := BuildOptions(cfg, nil, "")
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
		withoutPreWarm(),
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

// TestConfigMergeFromCarriesTemplatePath: template_path must merge like every
// other field, so an appsec-config that only sets the custom page doesn't wipe
// the tuning contributed by another one.
func TestConfigMergeFromCarriesTemplatePath(t *testing.T) {
	dst := &Config{CookieTTL: new(12 * time.Hour)}
	dst.MergeFrom(&Config{TemplatePath: new("pages/challenge.html")})

	require.NotNil(t, dst.TemplatePath)
	assert.Equal(t, "pages/challenge.html", *dst.TemplatePath)
	assert.Equal(t, 12*time.Hour, *dst.CookieTTL, "template_path must not wipe other fields")
}

// TestBuildOptionsCustomTemplate: a page carrying {{.CrowdsecChallenge}} is
// served instead of the built-in one, and the challenge machinery (PoW
// parameters, fingerprint scanner, challenge module) lands inside it.
func TestBuildOptionsCustomTemplate(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "page.html"), []byte("<body><h1>my own page</h1>{{.CrowdsecChallenge}}</body>"), 0o600))

	opts, err := BuildOptions(&Config{TemplatePath: new("page.html")}, nil, dataDir)
	require.NoError(t, err)

	rt, err := NewChallengeRuntime(t.Context(), append(opts, WithMasterSecret(testSecret), withoutPreWarm())...)
	require.NoError(t, err)

	html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
	require.NoError(t, err)

	assert.Contains(t, html, "<h1>my own page</h1>")
	assert.NotContains(t, html, "Why am I seeing this?", "the built-in page must not be served")

	for _, want := range []string{
		`<script src="` + ChallengeFPScannerPath + `">`,
		"var _powD=",
		"crowdsecSetChallengeStatus",
		"navigator.cookieEnabled",
	} {
		assert.Contains(t, html, want, "CrowdsecChallenge must carry the whole challenge engine")
	}
}

// TestBuildOptionsUnusableTemplate: an unusable custom page is a warning, not
// a startup failure — the built-in page keeps the instance protected. The
// missing-action case matters most: it parses and renders fine, but produces a
// page no visitor could ever solve.
func TestBuildOptionsUnusableTemplate(t *testing.T) {
	dataDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "no-action.html"), []byte("<body>forgot the challenge</body>"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "unparsable.html"), []byte("<body>{{.CrowdsecChallenge</body>"), 0o600))

	outside := filepath.Join(t.TempDir(), "outside.html")
	require.NoError(t, os.WriteFile(outside, []byte("<body>{{.CrowdsecChallenge}}</body>"), 0o600))

	tests := []struct {
		name string
		path string
	}{
		{name: "missing CrowdsecChallenge", path: "no-action.html"},
		{name: "unparsable template", path: "unparsable.html"},
		{name: "no such file", path: "absent.html"},
		{name: "absolute path", path: outside},
		{name: "escapes the data dir", path: "../" + filepath.Base(filepath.Dir(outside)) + "/outside.html"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := BuildOptions(&Config{TemplatePath: &tc.path}, nil, dataDir)
			require.NoError(t, err, "an unusable page must not fail the configuration")

			rt, err := NewChallengeRuntime(t.Context(), append(opts, WithMasterSecret(testSecret), withoutPreWarm())...)
			require.NoError(t, err)

			html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
			require.NoError(t, err)
			assert.Contains(t, html, "Why am I seeing this?", "the built-in page must be served instead")
		})
	}
}

// TestChallengePageAlwaysAttributesCrowdSec: the attribution ships inside
// {{.CrowdsecChallenge}}, which every page is required to carry, so a custom
// page gets it whether or not its author thought about it — and the built-in
// page must not end up showing it twice.
func TestChallengePageAlwaysAttributesCrowdSec(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "page.html"), []byte("<body>{{.CrowdsecChallenge}}</body>"), 0o600))

	opts, err := BuildOptions(&Config{TemplatePath: new("page.html")}, nil, dataDir)
	require.NoError(t, err)

	tests := []struct {
		name string
		opts []Option
	}{
		{name: "built-in page", opts: nil},
		{name: "custom page", opts: opts},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := NewChallengeRuntime(t.Context(), append(tc.opts, WithMasterSecret(testSecret), withoutPreWarm())...)
			require.NoError(t, err)

			html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
			require.NoError(t, err)

			assert.Contains(t, html, "Security check powered by")
			assert.Equal(t, 1, strings.Count(html, `id="crowdsec-attribution"`), "attribution must appear exactly once")
			assert.Contains(t, html, `href="https://crowdsec.net/"`)
		})
	}
}

// TestResolveTemplatePath pins the rules BuildOptions only reports as a
// warning: the page lives under the data dir, and nothing gets to point
// outside it.
func TestResolveTemplatePath(t *testing.T) {
	dataDir := filepath.Join(string(filepath.Separator), "var", "lib", "crowdsec", "data")

	tests := []struct {
		name    string
		dataDir string
		path    string
		want    string
		wantErr string
	}{
		{
			name:    "plain name",
			dataDir: dataDir,
			path:    "challenge.html",
			want:    filepath.Join(dataDir, "challenge.html"),
		},
		{
			name:    "subdirectory",
			dataDir: dataDir,
			path:    filepath.Join("pages", "challenge.html"),
			want:    filepath.Join(dataDir, "pages", "challenge.html"),
		},
		{
			name:    "trailing separator on the data dir",
			dataDir: dataDir + string(filepath.Separator),
			path:    "challenge.html",
			want:    filepath.Join(dataDir, "challenge.html"),
		},
		{
			name:    "inner traversal staying inside",
			dataDir: dataDir,
			path:    filepath.Join("pages", "..", "challenge.html"),
			want:    filepath.Join(dataDir, "challenge.html"),
		},
		{
			name:    "absolute",
			dataDir: dataDir,
			path:    filepath.Join(string(filepath.Separator), "etc", "passwd"),
			wantErr: "must be relative to the data dir",
		},
		{
			name:    "traversal",
			dataDir: dataDir,
			path:    filepath.Join("..", "..", "secret.html"),
			wantErr: "escapes the data dir",
		},
		{
			name:    "sibling directory sharing the prefix",
			dataDir: dataDir,
			path:    filepath.Join("..", "data-backup", "challenge.html"),
			wantErr: "escapes the data dir",
		},
		{
			name:    "no data dir",
			path:    "challenge.html",
			wantErr: "no data dir configured",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTemplatePath(tc.dataDir, tc.path)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
