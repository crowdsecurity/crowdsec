package challenge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPageOverridesValidation(t *testing.T) {
	long := strings.Repeat("a", maxPageValueLen+1)

	tests := []struct {
		name    string
		set     func(p *PageOverrides) error
		wantErr string
	}{
		{name: "title", set: func(p *PageOverrides) error { return p.SetTitle("Shop") }},
		{name: "title too long", set: func(p *PageOverrides) error { return p.SetTitle(strings.Repeat("a", maxPageTitleLen+1)) }, wantErr: "max 256"},
		{name: "description", set: func(p *PageOverrides) error { return p.SetMeta("description", "d") }},
		{name: "og", set: func(p *PageOverrides) error { return p.SetMeta("og:image:alt", "d") }},
		{name: "twitter", set: func(p *PageOverrides) error { return p.SetMeta("twitter:card", "summary") }},
		{name: "robots", set: func(p *PageOverrides) error { return p.SetMeta("robots", "noindex") }},
		{name: "mixed case", set: func(p *PageOverrides) error { return p.SetMeta("msapplication-TileColor", "#fff") }},
		{name: "attribute injection", set: func(p *PageOverrides) error { return p.SetMeta(`og:x" onload="`, "d") }, wantErr: "only letters"},
		{name: "tag injection", set: func(p *PageOverrides) error { return p.SetMeta("a><script>", "d") }, wantErr: "only letters"},
		{name: "space", set: func(p *PageOverrides) error { return p.SetMeta("a b", "d") }, wantErr: "only letters"},
		{name: "empty key", set: func(p *PageOverrides) error { return p.SetMeta("", "d") }, wantErr: "only letters"},
		{name: "meta too long", set: func(p *PageOverrides) error { return p.SetMeta("description", long) }, wantErr: "max 2048"},
		{name: "var", set: func(p *PageOverrides) error { return p.SetVar("brand_name", "Shop") }},
		{name: "var not a template identifier", set: func(p *PageOverrides) error { return p.SetVar("brand-name", "Shop") }, wantErr: "must be a letter"},
		{name: "var too long", set: func(p *PageOverrides) error { return p.SetVar("brand", long) }, wantErr: "max 2048"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.set(&PageOverrides{})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// Setting a key again replaces it, so only new keys count toward the cap.
func TestPageOverridesCaps(t *testing.T) {
	var p PageOverrides

	for i := range maxPageMetaTags {
		require.NoError(t, p.SetMeta("og:k"+strings.Repeat("x", i), "v"))
		require.NoError(t, p.SetVar("v"+strings.Repeat("x", i), "v"))
	}

	require.NoError(t, p.SetMeta("og:k", "replaced"))
	require.NoError(t, p.SetVar("v", "replaced"))
	require.ErrorContains(t, p.SetMeta("og:new", "v"), "already has 32 meta tags")
	require.ErrorContains(t, p.SetVar("new", "v"), "already has 32 vars")
}

func TestBuiltinPageOverrides(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(), WithMasterSecret(testSecret), withoutPreWarm())
	require.NoError(t, err)

	html, err := rt.GetChallengePage(t.Context(), "test-agent", 8, nil)
	require.NoError(t, err)
	require.Contains(t, html, "<title>CrowdSec Challenge</title>")
	require.NotContains(t, html, `property="og:`)

	var p PageOverrides
	require.NoError(t, p.SetTitle(`Shop <script>alert(1)</script>`))
	require.NoError(t, p.SetMeta("description", `say "hi"`))
	require.NoError(t, p.SetMeta("og:title", "Shop"))
	require.NoError(t, p.SetMeta("twitter:card", "summary"))
	require.NoError(t, p.SetMeta("og:title", "Shop & co"))
	require.NoError(t, p.SetMeta("article:author", "Shop"))
	require.NoError(t, p.SetMeta("http-equiv", "refresh"))

	html, err = rt.GetChallengePage(t.Context(), "test-agent", 8, &p)
	require.NoError(t, err)

	for _, want := range []string{
		"<title>Shop &lt;script&gt;alert(1)&lt;/script&gt;</title>",
		`<meta name="description" content="say &#34;hi&#34;" />`,
		`<meta property="og:title" content="Shop &amp; co" />`,
		`<meta name="twitter:card" content="summary" />`,
		`<meta property="article:author" content="Shop" />`,
		// http-equiv is only a name here, so the browser ignores it.
		`<meta name="http-equiv" content="refresh" />`,
	} {
		require.Contains(t, html, want)
	}

	require.Equal(t, 1, strings.Count(html, `og:title`), "setting a meta key twice must replace it")
}

func TestCustomPageOverrides(t *testing.T) {
	dataDir := t.TempDir()
	page := `<html><head><title>{{.Title}}</title>{{.Meta}}</head>` +
		`<body><h1>[{{.Vars.brand}}]</h1><p>[{{.Vars.unset}}]</p>{{.CrowdsecChallenge}}</body></html>`
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "page.html"), []byte(page), 0o600))

	opts, err := BuildOptions(&Config{TemplatePath: new("page.html")}, nil, dataDir)
	require.NoError(t, err)

	rt, err := NewChallengeRuntime(t.Context(), append(opts, WithMasterSecret(testSecret), withoutPreWarm())...)
	require.NoError(t, err)

	var p PageOverrides
	require.NoError(t, p.SetTitle("Shop"))
	require.NoError(t, p.SetMeta("og:title", "Shop"))
	require.NoError(t, p.SetVar("brand", "<i>Shop</i>"))

	html, err := rt.GetChallengePage(t.Context(), "test-agent", 8, &p)
	require.NoError(t, err)

	require.Contains(t, html, "<title>Shop</title>")
	require.Contains(t, html, `<meta property="og:title" content="Shop" />`)
	require.Contains(t, html, "<h1>[&lt;i&gt;Shop&lt;/i&gt;]</h1>")
	require.Contains(t, html, "<p>[]</p>", "an unset var must render empty")
}
