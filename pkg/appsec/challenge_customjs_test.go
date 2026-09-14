package appsec

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
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

func TestReadCustomJS(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		data  []*enrichment.DataProvider
		want  []string // dest_file of each module, in order
	}{
		{
			name:  "single script",
			files: map[string]string{"challenge/custom.js": "hookA();"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/custom.js")},
			want:  []string{"challenge/custom.js"},
		},
		{
			// A base detection bundle and a site-specific fix compose, and hook
			// order follows the declaration order.
			name:  "read in declaration order",
			files: map[string]string{"challenge/a.js": "hookA()", "challenge/b.js": "hookB()"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/a.js"), challengeJSData("challenge/b.js")},
			want:  []string{"challenge/a.js", "challenge/b.js"},
		},
		{
			// esbuild resolves a module once per path, so the repeat would
			// register the same hook twice.
			name:  "repeated dest_file read once",
			files: map[string]string{"challenge/a.js": "hookA()"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/a.js"), challengeJSData("challenge/a.js")},
			want:  []string{"challenge/a.js"},
		},
		{
			name:  "other data types ignored",
			files: map[string]string{"legit_bots/gptbot.json": "{}", "crs/rules.conf": "SecRule"},
			data: []*enrichment.DataProvider{
				{DestPath: "legit_bots/gptbot.json", Type: "bots"},
				{DestPath: "crs/rules.conf", Type: "modsec"},
			},
		},
		{
			// Bot detection has to survive a data file that hasn't downloaded.
			name:  "missing file skipped",
			files: map[string]string{"challenge/present.js": "hookB()"},
			data:  []*enrichment.DataProvider{challengeJSData("challenge/absent.js"), challengeJSData("challenge/present.js")},
			want:  []string{"challenge/present.js"},
		},
		{
			name: "empty dest_file skipped",
			data: []*enrichment.DataProvider{{Type: exprhelpers.ChallengeJSDataType}},
		},
		{
			name: "no data at all",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, dataDir := challengeJSConfig(t, tc.files, tc.data...)

			var got []string
			for _, d := range cfg.readCustomJS(dataDir) {
				got = append(got, d.Name)
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

// The point of compiling each module separately: one file that cannot be built
// used to cost every other detector its registration.
func TestLoadCustomJSDropsBrokenScript(t *testing.T) {
	cfg, dataDir := challengeJSConfig(t,
		map[string]string{
			"challenge/broken.js": "export function collectSignals(fp) {\n",
			"challenge/good.js":   "export function collectSignals(fp) { fp.custom = { ok: \"GOOD\" } }\n",
		},
		challengeJSData("challenge/broken.js"), challengeJSData("challenge/good.js"))

	out := cfg.LoadCustomJS(dataDir)

	require.NotEmpty(t, out)
	assert.Contains(t, out, "GOOD")
	assert.Contains(t, out, "__CSEC_CUSTOM_DETECT_v1__")
}

func TestLoadCustomJSRejectsTraversal(t *testing.T) {
	cfg, dataDir := challengeJSConfig(t, nil, challengeJSData("../outside.js"))
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(dataDir), "outside.js"), []byte("pwn()"), 0o600))

	assert.Empty(t, cfg.readCustomJS(dataDir))
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

// Startup noise scales with the number of installed scripts unless the summary
// is one line and the per-script detail sits at debug.
func TestLoadCustomJSLogsOneSummary(t *testing.T) {
	src := "export function collectSignals(fp) { fp.custom = { ok: true } }\n"

	capture, hook := logtest.NewNullLogger()
	capture.SetLevel(log.DebugLevel)

	cfg, dataDir := challengeJSConfig(t,
		map[string]string{"challenge/a.js": src, "challenge/b.js": src},
		challengeJSData("challenge/a.js"), challengeJSData("challenge/b.js"))
	cfg.Logger = log.NewEntry(capture)

	out := cfg.LoadCustomJS(dataDir)
	require.NotEmpty(t, out)

	var (
		infos  []*log.Entry
		debugs int
	)

	for _, e := range hook.AllEntries() {
		switch e.Level {
		case log.InfoLevel:
			infos = append(infos, e)
		case log.DebugLevel:
			debugs++
		}
	}

	require.Len(t, infos, 1, "per-script detail belongs at debug")
	require.Equal(t, 2, debugs)

	// Declaration order is hook order, so the summary reports it as declared.
	require.Equal(t, "challenge/a.js, challenge/b.js", infos[0].Data["scripts"])
	require.Equal(t, challenge.CustomJSVersion(out), infos[0].Data["version"])
}

// Nothing served means nothing to summarize: the rejection error already named
// the file, and a summary line here would claim a script the browser never gets.
func TestLoadCustomJSAllRejected(t *testing.T) {
	capture, hook := logtest.NewNullLogger()

	cfg, dataDir := challengeJSConfig(t,
		map[string]string{"challenge/broken.js": "export function collectSignals(fp) {\n"},
		challengeJSData("challenge/broken.js"))
	cfg.Logger = log.NewEntry(capture)

	require.Empty(t, cfg.LoadCustomJS(dataDir))

	for _, e := range hook.AllEntries() {
		require.NotEqual(t, log.InfoLevel, e.Level, e.Message)
	}
}
