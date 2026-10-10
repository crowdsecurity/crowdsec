package challenge

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
)

func TestPartitionedChallengeCookies(t *testing.T) {
	for _, tc := range []struct {
		name        string
		config      string
		scheme      string
		partitioned bool
	}{
		{name: "default HTTP", scheme: "http"},
		{name: "default HTTPS", scheme: "https"},
		{name: "explicit false", config: "cookie_partitioned: false", scheme: "https"},
		{name: "partitioned HTTPS", config: "cookie_partitioned: true", scheme: "https", partitioned: true},
		// TLS may terminate at the bouncer, so Secure cannot depend on the forwarded scheme.
		{name: "partitioned forwarded HTTP", config: "cookie_partitioned: true", scheme: "http", partitioned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			require.NoError(t, yaml.Unmarshal([]byte(tc.config), &cfg))
			opts, err := BuildOptions(&cfg, nil)
			require.NoError(t, err)
			opts = append(opts, WithMasterSecret(testSecret), WithRotationInterval(time.Minute), withoutPreWarm())
			rt, err := NewChallengeRuntime(t.Context(), opts...)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, rt.Close(t.Context())) })

			page, err := rt.GetChallengePage(t.Context(), "test-agent", PowDifficultyDisabled)
			require.NoError(t, err)
			attrs := "path=/; SameSite=Lax"
			sameSite := http.SameSiteLaxMode
			if tc.partitioned {
				attrs = "path=/; SameSite=None; Secure; Partitioned"
				sameSite = http.SameSiteNoneMode
				require.NotContains(t, page, "SameSite=Lax")
			} else {
				require.NotContains(t, page, "Partitioned")
			}
			require.Contains(t, page, `document.cookie = "__crowdsec_cookie_test=1; `+attrs+`";`)
			require.Contains(t, page, `document.cookie = "__crowdsec_cookie_test=; `+attrs+`; Max-Age=0";`)

			for _, allowlisted := range []bool{false, true} {
				name := "successful challenge"
				if allowlisted {
					name = "allowlist"
				}
				t.Run(name, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.scheme+"://example.test/submit", nil)
					require.NoError(t, err)
					req.Header.Set("User-Agent", "test-agent")
					var ck *cookie.AppsecCookie
					if allowlisted {
						ck, err = rt.SealAllowlistCookie(req, "trusted bot", nil)
					} else {
						r, ts := freshChallenge(t)
						body := buildValidBody(t, PowDifficultyDisabled, r, ts)
						ck, _, _, err = rt.ValidateChallengeResponse(req, []byte(body))
					}
					require.NoError(t, err)
					parsed, err := http.ParseSetCookie(ck.String())
					require.NoError(t, err)
					require.NoError(t, parsed.Valid())
					require.Equal(t, ChallengeCookieName, parsed.Name)
					require.Equal(t, "/", parsed.Path)
					require.Empty(t, parsed.Domain)
					require.True(t, parsed.HttpOnly)
					require.Equal(t, sameSite, parsed.SameSite)
					require.Equal(t, tc.partitioned, parsed.Partitioned)
					require.Equal(t, tc.partitioned || tc.scheme == "https", parsed.Secure)
					require.Positive(t, parsed.MaxAge)
					data, err := rt.ValidCookie(parsed, "test-agent")
					require.NoError(t, err)
					require.Equal(t, allowlisted, data.Allowlisted)
				})
			}
		})
	}
}

func TestCookiePartitionedConfigMerge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		overlay  string
		expected bool
	}{
		{name: "unset preserves opt-in", expected: true},
		{name: "explicit true", overlay: "cookie_partitioned: true", expected: true},
		{name: "explicit false disables", overlay: "cookie_partitioned: false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg, overlay Config
			require.NoError(t, yaml.Unmarshal([]byte("cookie_partitioned: true"), &cfg))
			require.NoError(t, yaml.Unmarshal([]byte(tc.overlay), &overlay))
			cfg.MergeFrom(&overlay)
			opts, err := BuildOptions(&cfg, nil)
			require.NoError(t, err)
			rt, err := NewChallengeRuntime(t.Context(), append(opts, WithMasterSecret(testSecret), withoutPreWarm())...)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, rt.Close(t.Context())) })
			ck, err := rt.SealAllowlistCookie(&http.Request{URL: mustURL("http://example.test/")}, "trusted bot", nil)
			require.NoError(t, err)
			parsed, err := http.ParseSetCookie(ck.String())
			require.NoError(t, err)
			require.Equal(t, tc.expected, parsed.Partitioned)
		})
	}
}
