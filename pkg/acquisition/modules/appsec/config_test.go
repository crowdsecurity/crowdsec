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

// hubWithConfigs builds an in-memory hub holding the given appsec-configs and
// marks the listed ones as installed (an installed item is one with a
// LocalPath, see cwhub.ItemState.IsInstalled).
func hubWithConfigs(t *testing.T, all, installed []string) *cwhub.Hub {
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

	index := `{"appsec-configs": {`
	for i, name := range all {
		if i > 0 {
			index += ","
		}
		index += `"` + name + `": {"path": "appsec-configs/` + name + `.yaml", "version": "1.0", "versions": {"1.0": {"digest": "aa"}}}`
	}
	index += "}}"

	require.NoError(t, os.WriteFile(local.HubIndexFile, []byte(index), 0o644))

	hub, err := cwhub.NewHub(local, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Load())

	for _, name := range installed {
		item := hub.GetItem(cwhub.APPSEC_CONFIGS, name)
		require.NotNilf(t, item, "appsec-config %q missing from test hub", name)
		item.State.LocalPath = filepath.Join(local.InstallDir, name+".yaml")
	}

	return hub
}

func TestExpandAppsecConfigEntry(t *testing.T) {
	all := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "crowdsecurity/uninstalled", "custom/mine"}
	installed := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "custom/mine"}

	tests := []struct {
		name        string
		entry       string
		expected    []string
		expectedErr string
	}{
		{
			// Literals pass through untouched, even unknown ones, so the
			// per-name error still surfaces later from AppsecConfig.Load.
			name:     "literal passthrough",
			entry:    "crowdsecurity/vpatch",
			expected: []string{"crowdsecurity/vpatch"},
		},
		{
			name:     "unknown literal passthrough",
			entry:    "does/not-exist",
			expected: []string{"does/not-exist"},
		},
		{
			// Sorted (case-insensitive) order from the hub; uninstalled is skipped.
			name:     "wildcard expands installed only",
			entry:    "crowdsecurity/*",
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch"},
		},
		{
			name:     "wildcard matches all",
			entry:    "*",
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch", "custom/mine"},
		},
		{
			name:        "wildcard with no match errors",
			entry:       "nope/*",
			expectedErr: `no installed appsec-config matches pattern "nope/*"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := hubWithConfigs(t, all, installed)

			got, err := expandAppsecConfigEntry(tc.entry, hub)
			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestResolveAppsecConfigEntries(t *testing.T) {
	all := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "crowdsecurity/uninstalled", "custom/mine"}
	installed := []string{"crowdsecurity/vpatch", "crowdsecurity/generic", "custom/mine"}

	tests := []struct {
		name     string
		entries  []string
		expected []string
	}{
		{
			// "*" already pulls in vpatch; the explicit literal must not load it
			// a second time. First-seen order from the wildcard expansion wins.
			name:     "wildcard plus overlapping literal dedups",
			entries:  []string{"*", "crowdsecurity/vpatch"},
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch", "custom/mine"},
		},
		{
			name:     "same literal twice collapses to one",
			entries:  []string{"crowdsecurity/vpatch", "crowdsecurity/vpatch"},
			expected: []string{"crowdsecurity/vpatch"},
		},
		{
			name:     "unknown literal passes through once",
			entries:  []string{"does/not-exist", "does/not-exist"},
			expected: []string{"does/not-exist"},
		},
		{
			// Overlapping patterns: generic matches both, must appear once.
			name:     "overlapping patterns dedup",
			entries:  []string{"crowdsecurity/*", "*/generic"},
			expected: []string{"crowdsecurity/generic", "crowdsecurity/vpatch"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := hubWithConfigs(t, all, installed)

			got, err := resolveAppsecConfigEntries(tc.entries, hub)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}
