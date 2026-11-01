package challenge

import (
	"regexp"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
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

// The script is served uncached, so the page must point at the bare path: a
// query the dispatcher does not route on would only be dead weight.
func TestCustomJSURLIsUnversioned(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		WithMasterSecret(testSecret), WithCustomJS("hookA();"), withoutPreWarm())
	require.NoError(t, err)

	html, err := rt.GetChallengePage(t.Context(), "test-agent", 8)
	require.NoError(t, err)

	require.Contains(t, html, ChallengeCustomJSPath)
	assert.NotRegexp(t, regexp.QuoteMeta(ChallengeCustomJSPath)+`\?`, html)
}

// The startup summary is where an operator confirms which build of the shipped
// detections an engine is running.
func TestChallengeRuntimeSummaryCarriesCustomJS(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{name: "with a script", script: "hookA();"},
		{name: "without a script"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capture, hook := logtest.NewNullLogger()

			opts := []Option{WithMasterSecret(testSecret), withoutPreWarm(), WithLogger(log.NewEntry(capture))}
			if tc.script != "" {
				opts = append(opts, WithCustomJS(tc.script))
			}

			_, err := NewChallengeRuntime(t.Context(), opts...)
			require.NoError(t, err)

			var summary *log.Entry

			for _, e := range hook.AllEntries() {
				if e.Message == "WAF challenge runtime initialized" {
					summary = e
				}
			}

			require.NotNil(t, summary)

			// No script means no empty fields: an empty version on every
			// challenge-mode startup would read as a failed load.
			if tc.script == "" {
				require.NotContains(t, summary.Data, "custom_js_version")
				require.NotContains(t, summary.Data, "custom_js_timeout")

				return
			}

			require.Equal(t, CustomJSVersion(tc.script), summary.Data["custom_js_version"])
			require.Equal(t, DefaultCustomJSTimeout, summary.Data["custom_js_timeout"])
		})
	}
}
