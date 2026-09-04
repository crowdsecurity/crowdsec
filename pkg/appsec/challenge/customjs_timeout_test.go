package challenge

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomJSTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want time.Duration
	}{
		{name: "unset", want: DefaultCustomJSTimeout},
		{name: "configured", opts: []Option{WithCustomJSTimeout(1500 * time.Millisecond)}, want: 1500 * time.Millisecond},
		// Zero and negative fall back rather than disabling the budget: a page
		// with no deadline would let one bad hook hang every visitor.
		{name: "zero", opts: []Option{WithCustomJSTimeout(0)}, want: DefaultCustomJSTimeout},
		{name: "negative", opts: []Option{WithCustomJSTimeout(-time.Second)}, want: DefaultCustomJSTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := NewChallengeRuntime(t.Context(), append(tc.opts, withoutPreWarm())...)
			require.NoError(t, err)

			assert.Equal(t, tc.want, rt.customJSTimeout)
		})
	}
}

// The value only matters if it reaches the browser, and it rides the same
// inline-var mechanism as the PoW parameters.
func TestCustomJSTimeoutReachesThePage(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{name: "default", want: "_cjsT=500"},
		{name: "configured", opts: []Option{WithCustomJSTimeout(1500 * time.Millisecond)}, want: "_cjsT=1500"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := NewChallengeRuntime(t.Context(), append(tc.opts, WithMasterSecret(testSecret), withoutPreWarm())...)
			require.NoError(t, err)

			html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
			require.NoError(t, err)

			assert.Contains(t, html, tc.want)
		})
	}
}

func TestCustomJSTimeoutConfig(t *testing.T) {
	d := 2 * time.Second

	t.Run("MergeFrom takes a non-nil value", func(t *testing.T) {
		c := &Config{}
		c.MergeFrom(&Config{CustomJSTimeout: &d})
		require.NotNil(t, c.CustomJSTimeout)
		assert.Equal(t, d, *c.CustomJSTimeout)
	})

	t.Run("MergeFrom leaves an unset value alone", func(t *testing.T) {
		c := &Config{CustomJSTimeout: &d}
		c.MergeFrom(&Config{})
		require.NotNil(t, c.CustomJSTimeout)
		assert.Equal(t, d, *c.CustomJSTimeout)
	})

	t.Run("BuildOptions carries it to the runtime", func(t *testing.T) {
		opts, err := BuildOptions(&Config{CustomJSTimeout: &d}, nil)
		require.NoError(t, err)

		var resolved runtimeOptions
		for _, o := range opts {
			o(&resolved)
		}

		assert.Equal(t, d, resolved.customJSTimeout)
	})
}

// Guards the JS-side contract: the injected name and the name the bundle reads
// are built separately and only meet on this string.
func TestCustomJSTimeoutVarNameMatchesBundle(t *testing.T) {
	rt := &ChallengeRuntime{}
	require.NoError(t, rt.seedCacheFromInitialBundle())

	assert.Contains(t, rt.getChallengeCode(), "_cjsT",
		"the obfuscated bundle must still read the injected _cjsT var")
	assert.Contains(t, htmlTemplate, "_cjsT=",
		"the challenge page must still inject _cjsT")
}

// The script is cached for an hour, so its URL has to change when it does —
// otherwise a returning visitor keeps running old detections against new
// scoring rules, with nothing to indicate it.
func TestCustomJSURLIsVersionedByContent(t *testing.T) {
	page := func(t *testing.T, script string) string {
		t.Helper()

		rt, err := NewChallengeRuntime(t.Context(),
			WithMasterSecret(testSecret), WithCustomJS(script), withoutPreWarm())
		require.NoError(t, err)

		html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
		require.NoError(t, err)

		return html
	}

	first := page(t, "hookA();")
	again := page(t, "hookA();")
	changed := page(t, "hookB();")

	ref := regexp.MustCompile(`/crowdsec-internal/challenge/custom\.js\?v=([0-9a-f]+)`)

	v1 := ref.FindStringSubmatch(first)
	v2 := ref.FindStringSubmatch(again)
	v3 := ref.FindStringSubmatch(changed)

	require.NotNil(t, v1, "challenge page must reference a versioned custom.js")
	require.NotNil(t, v3)

	assert.Equal(t, v1[1], v2[1], "same script must keep the same URL, so the cache still works")
	assert.NotEqual(t, v1[1], v3[1], "a changed script must change the URL")
}

// The version is a cache key only: the dispatcher routes on path, so the served
// path itself must stay clean.
func TestCustomJSPathUnversioned(t *testing.T) {
	assert.NotContains(t, ChallengeCustomJSPath, "?")
}
