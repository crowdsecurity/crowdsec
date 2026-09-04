package appsec

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

func challengeJSConfig(t *testing.T, files map[string]string, data ...*enrichment.DataProvider) (*AppsecConfig, string) {
	t.Helper()

	dataDir := t.TempDir()

	for rel, content := range files {
		path := filepath.Join(dataDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	return &AppsecConfig{
		Name:   "test",
		Data:   data,
		Logger: log.NewEntry(log.StandardLogger()),
	}, dataDir
}

func challengeJSData(dest string) *enrichment.DataProvider {
	return &enrichment.DataProvider{DestPath: dest, Type: exprhelpers.ChallengeJSDataType}
}

func TestLoadCustomJS(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		data  []*enrichment.DataProvider
		want  string
	}{
		{
			name:  "single script",
			files: map[string]string{"challenge/custom.js": "hookA();"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/custom.js")},
			want:  "hookA();",
		},
		{
			// A base detection bundle and a site-specific fix compose. The
			// separator keeps a file with no trailing newline or semicolon from
			// splicing into the next.
			name:  "concatenated in declaration order",
			files: map[string]string{"challenge/a.js": "hookA()", "challenge/b.js": "hookB()"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/a.js"), challengeJSData("challenge/b.js")},
			want:  "hookA()\n;\nhookB()",
		},
		{
			name:  "other data types ignored",
			files: map[string]string{"legit_bots/gptbot.json": "{}", "crs/rules.conf": "SecRule"},
			data: []*enrichment.DataProvider{
				{DestPath: "legit_bots/gptbot.json", Type: "bots"},
				{DestPath: "crs/rules.conf", Type: "modsec"},
			},
			want: "",
		},
		{
			// Bot detection has to survive a data file that hasn't downloaded.
			name:  "missing file skipped",
			files: map[string]string{"challenge/present.js": "hookB()"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/absent.js"), challengeJSData("challenge/present.js")},
			want:  "hookB()",
		},
		{
			name: "empty dest_file skipped",
			data: []*enrichment.DataProvider{{Type: exprhelpers.ChallengeJSDataType}},
			want: "",
		},
		{
			name: "no data at all",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, dataDir := challengeJSConfig(t, tc.files, tc.data...)
			assert.Equal(t, tc.want, cfg.LoadCustomJS(dataDir))
		})
	}
}

func TestLoadCustomJSRejectsTraversal(t *testing.T) {
	cfg, dataDir := challengeJSConfig(t, nil, challengeJSData("../outside.js"))
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(dataDir), "outside.js"), []byte("pwn()"), 0o600))

	assert.Empty(t, cfg.LoadCustomJS(dataDir))
}

// Without the early return in FileInit, an unknown data type reaches
// existsInFileMaps and errors, so every startup logs a spurious failure.
func TestChallengeJSDataTypeIsNotExprData(t *testing.T) {
	_, dataDir := challengeJSConfig(t, map[string]string{"challenge/custom.js": "not data, just JS\n"})

	require.NoError(t, exprhelpers.FileInit(dataDir, "challenge/custom.js", exprhelpers.ChallengeJSDataType))
}

// custom_js_timeout has to load through LoadByPath, which is a strict unmarshal:
// an unrecognized key there is a hard failure, not a warning.
func TestChallengeCustomJSTimeoutLoadsFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")

	require.NoError(t, os.WriteFile(path, []byte(
		"name: test/custom-js-timeout\nchallenge:\n  custom_js_timeout: 1500ms\n"), 0o600))

	cfg, _ := challengeJSConfig(t, nil)
	require.NoError(t, cfg.LoadByPath(path))

	require.NotNil(t, cfg.Challenge)
	require.NotNil(t, cfg.Challenge.CustomJSTimeout)
	assert.Equal(t, 1500*time.Millisecond, *cfg.Challenge.CustomJSTimeout)
}
