package challenge

import (
	"net/http"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

// Both challenge cookies and the page's cookies-enabled probe must carry the
// configured SameSite mode, or the challenge loops inside a cross-site iframe.
func TestChallengeCookieSameSite(t *testing.T) {
	tests := []struct {
		name          string
		sameSiteNone  bool
		scheme        string
		wantAttrs     []string
		forbidAttrs   []string
		wantTestProbe string
	}{
		{
			name:          "lax over http",
			scheme:        "http",
			wantAttrs:     []string{"SameSite=Lax", "HttpOnly"},
			forbidAttrs:   []string{"Secure", "Partitioned", "SameSite=None"},
			wantTestProbe: "path=/; SameSite=Lax",
		},
		{
			name:          "lax over https",
			scheme:        "https",
			wantAttrs:     []string{"SameSite=Lax", "HttpOnly", "Secure"},
			forbidAttrs:   []string{"Partitioned", "SameSite=None"},
			wantTestProbe: "path=/; SameSite=Lax",
		},
		{
			// Behind a bouncer the scheme seen by the WAF is often http.
			name:          "none over http is still secure",
			sameSiteNone:  true,
			scheme:        "http",
			wantAttrs:     []string{"SameSite=None", "HttpOnly", "Secure", "Partitioned"},
			forbidAttrs:   []string{"SameSite=Lax"},
			wantTestProbe: "path=/; SameSite=None; Secure; Partitioned",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestRuntimeWithDifficulty(8)
			c.cookieSameSiteNone = tc.sameSiteNone

			r, ts := freshChallenge(t)
			body := buildValidBody(t, c.powDifficulty, r, ts)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.scheme+"://example.com/submit", strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("User-Agent", "test-agent")

			challengeCk, _, _, err := c.ValidateChallengeResponse(req, []byte(body))
			require.NoError(t, err)

			allowlistCk, err := c.SealAllowlistCookie(req, "test", nil)
			require.NoError(t, err)

			for _, setCookie := range []string{challengeCk.String(), allowlistCk.String()} {
				attrs := strings.Split(setCookie, "; ")
				for _, want := range tc.wantAttrs {
					require.Contains(t, attrs, want, setCookie)
				}
				for _, forbid := range tc.forbidAttrs {
					require.NotContains(t, attrs, forbid, setCookie)
				}
			}

			tpl, err := template.New("challenge").Parse(htmlTemplate)
			require.NoError(t, err)

			var page strings.Builder
			require.NoError(t, tpl.Execute(&page, map[string]any{"TestCookieAttrs": c.testCookieAttrs()}))
			require.Contains(t, page.String(), `document.cookie = "__crowdsec_cookie_test=1; `+tc.wantTestProbe+`";`)
			require.Contains(t, page.String(), `document.cookie = "__crowdsec_cookie_test=; `+tc.wantTestProbe+`; Max-Age=0";`)
		})
	}
}

func TestBuildOptionsCookieSameSite(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantNone bool
		wantErr  string
	}{
		{name: "lax", value: "lax"},
		{name: "none", value: "none", wantNone: true},
		{name: "case insensitive", value: "None", wantNone: true},
		{name: "strict rejected", value: "strict", wantErr: `invalid challenge cookie_same_site "strict"`},
		{name: "garbage rejected", value: "foo", wantErr: `invalid challenge cookie_same_site "foo"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := BuildOptions(&Config{CookieSameSite: new(tc.value)}, nil)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			rt, err := NewChallengeRuntime(t.Context(), append(opts, withoutPreWarm())...)
			require.NoError(t, err)

			require.Equal(t, tc.wantNone, rt.cookieSameSiteNone)
		})
	}
}
