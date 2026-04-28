package appsecacquisition

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// newTestHub builds an in-memory hub from a JSON index. It mirrors the
// `testHub` helper used in pkg/cwhub but is duplicated here because that helper
// is unexported.
func newTestHub(t *testing.T, indexJSON string) *cwhub.Hub {
	t.Helper()

	tempDir := t.TempDir()
	local := &csconfig.LocalHubCfg{
		HubDir:         filepath.Join(tempDir, "hub"),
		HubIndexFile:   filepath.Join(tempDir, "hub", ".index.json"),
		InstallDir:     filepath.Join(tempDir, "install"),
		InstallDataDir: filepath.Join(tempDir, "data"),
	}

	require.NoError(t, os.MkdirAll(local.HubDir, 0o755))
	require.NoError(t, os.MkdirAll(local.InstallDir, 0o755))
	require.NoError(t, os.MkdirAll(local.InstallDataDir, 0o755))
	require.NoError(t, os.WriteFile(local.HubIndexFile, []byte(indexJSON), 0o644))

	hub, err := cwhub.NewHub(local, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Load())

	return hub
}

// markInstalled flags an appsec-config hub item as installed by setting its
// LocalPath, which is what ItemState.IsInstalled() checks.
func markInstalled(t *testing.T, hub *cwhub.Hub, name string) {
	t.Helper()

	item := hub.GetItem(cwhub.APPSEC_CONFIGS, name)
	require.NotNilf(t, item, "appsec-config %q missing from test hub", name)
	item.State.LocalPath = filepath.Join("/fake/install", item.Type, name+".yaml")
}

// hubFixture sets up a hub with three appsec-configs under crowdsecurity/* and
// one under custom/*. Two of the crowdsecurity items are marked installed; the
// custom one is also installed; one crowdsecurity item is left uninstalled to
// verify wildcard expansion ignores it.
const hubFixtureIndex = `{
  "appsec-configs": {
    "crowdsecurity/vpatch": {
      "path": "appsec-configs/crowdsecurity/vpatch.yaml",
      "version": "1.0",
      "versions": {"1.0": {"digest": "aa"}}
    },
    "crowdsecurity/generic": {
      "path": "appsec-configs/crowdsecurity/generic.yaml",
      "version": "1.0",
      "versions": {"1.0": {"digest": "bb"}}
    },
    "crowdsecurity/uninstalled": {
      "path": "appsec-configs/crowdsecurity/uninstalled.yaml",
      "version": "1.0",
      "versions": {"1.0": {"digest": "cc"}}
    },
    "custom/my-config": {
      "path": "appsec-configs/custom/my-config.yaml",
      "version": "1.0",
      "versions": {"1.0": {"digest": "dd"}}
    }
  }
}`

func newPopulatedHub(t *testing.T) *cwhub.Hub {
	t.Helper()
	hub := newTestHub(t, hubFixtureIndex)
	markInstalled(t, hub, "crowdsecurity/vpatch")
	markInstalled(t, hub, "crowdsecurity/generic")
	markInstalled(t, hub, "custom/my-config")
	return hub
}

func TestResolveAppsecConfigEntry_LiteralPassThrough(t *testing.T) {
	hub := newPopulatedHub(t)

	// Literal entries are returned as-is without consulting the hub. This
	// preserves the existing per-name "no appsec-config found for X" error
	// path inside AppsecConfig.Load for typos.
	got, err := resolveAppsecConfigEntry("crowdsecurity/vpatch", hub)
	require.NoError(t, err)
	assert.Equal(t, []string{"crowdsecurity/vpatch"}, got)

	got, err = resolveAppsecConfigEntry("does/not-exist", hub)
	require.NoError(t, err)
	assert.Equal(t, []string{"does/not-exist"}, got)
}

func TestResolveAppsecConfigEntry_WildcardExpands(t *testing.T) {
	hub := newPopulatedHub(t)

	got, err := resolveAppsecConfigEntry("crowdsecurity/*", hub)
	require.NoError(t, err)
	// Only installed items match; sorted (case-insensitive) order from the hub.
	assert.Equal(t, []string{"crowdsecurity/generic", "crowdsecurity/vpatch"}, got)
}

func TestResolveAppsecConfigEntry_WildcardMatchesAll(t *testing.T) {
	hub := newPopulatedHub(t)

	got, err := resolveAppsecConfigEntry("*", hub)
	require.NoError(t, err)
	assert.Equal(t, []string{"crowdsecurity/generic", "crowdsecurity/vpatch", "custom/my-config"}, got)
}

func TestResolveAppsecConfigEntry_QuestionMark(t *testing.T) {
	hub := newPopulatedHub(t)

	// '?' matches a single character, so this should match neither
	// "crowdsecurity/vpatch" nor "crowdsecurity/generic".
	_, err := resolveAppsecConfigEntry("crowdsecurity/?", hub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no installed appsec-config matches pattern")
}

func TestResolveAppsecConfigEntry_NoMatchErrors(t *testing.T) {
	hub := newPopulatedHub(t)

	_, err := resolveAppsecConfigEntry("nope/*", hub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no installed appsec-config matches pattern "nope/*"`)
}

func TestResolveAppsecConfigEntry_WildcardSkipsUninstalled(t *testing.T) {
	hub := newPopulatedHub(t)

	got, err := resolveAppsecConfigEntry("crowdsecurity/*", hub)
	require.NoError(t, err)
	// "crowdsecurity/uninstalled" is in the index but not installed, so it
	// must not appear in the expansion.
	assert.NotContains(t, got, "crowdsecurity/uninstalled")
}
