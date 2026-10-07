package leakybucket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// hubFile is an item file, either from the hub (indexed and installed with a symlink) or local.
type hubFile struct {
	itemType string
	name     string // author/name
	content  string
	local    bool
	tainted  bool // modified after being indexed
}

func buildHub(t *testing.T, files []hubFile) *cwhub.Hub {
	t.Helper()

	dir := t.TempDir()
	local := &csconfig.LocalHubCfg{
		HubDir:         filepath.Join(dir, "hub"),
		HubIndexFile:   filepath.Join(dir, "hub", ".index.json"),
		InstallDir:     filepath.Join(dir, "install"),
		InstallDataDir: filepath.Join(dir, "data"),
	}

	index := map[string]map[string]any{}

	for _, f := range files {
		installPath := filepath.Join(local.InstallDir, f.itemType, filepath.Base(f.name)+".yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(installPath), 0o755))

		if f.local {
			require.NoError(t, os.WriteFile(installPath, []byte(f.content), 0o644))
			continue
		}

		remotePath := filepath.Join(f.itemType, f.name+".yaml")
		hubPath := filepath.Join(local.HubDir, remotePath)
		require.NoError(t, os.MkdirAll(filepath.Dir(hubPath), 0o755))

		sum := sha256.Sum256([]byte(f.content))

		content := f.content
		if f.tainted {
			content += "\n# local change\n"
		}

		require.NoError(t, os.WriteFile(hubPath, []byte(content), 0o644))
		require.NoError(t, os.Symlink(hubPath, installPath))

		if index[f.itemType] == nil {
			index[f.itemType] = map[string]any{}
		}

		index[f.itemType][f.name] = map[string]any{
			"path":     remotePath,
			"version":  "0.1",
			"versions": map[string]any{"0.1": map[string]string{"digest": hex.EncodeToString(sum[:])}},
		}
	}

	raw, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(local.HubDir, 0o755))
	require.NoError(t, os.WriteFile(local.HubIndexFile, raw, 0o644))

	hub, err := cwhub.NewHub(local, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Load())

	return hub
}

func TestScenarioVersionWithMacros(t *testing.T) {
	scenario := func(filter string) hubFile {
		return hubFile{
			itemType: cwhub.SCENARIOS,
			name:     "crowdsecurity/test",
			content:  "type: trigger\nname: crowdsecurity/test\ndescription: test\nfilter: \"" + filter + "\"\n",
		}
	}

	macro := hubFile{itemType: cwhub.MACROS, name: "crowdsecurity/macros", content: "macros:\n  IsFoo: evt.Line.Raw != ''\n"}

	tainted := macro
	tainted.tainted = true

	localMacro := macro
	localMacro.local = true

	localScenario := scenario("IsFoo()")
	localScenario.local = true

	tests := []struct {
		name    string
		files   []hubFile
		version string
	}{
		{
			name:    "hub macro",
			files:   []hubFile{scenario("IsFoo()"), macro},
			version: "0.1",
		},
		{
			name:    "tainted macro",
			files:   []hubFile{scenario("IsFoo()"), tainted},
			version: "?",
		},
		{
			name:    "local macro",
			files:   []hubFile{scenario("IsFoo()"), localMacro},
			version: "?",
		},
		{
			name:    "tainted macro not used by the scenario",
			files:   []hubFile{scenario("evt.Line.Raw != ''"), tainted},
			version: "0.1",
		},
		{
			// stays custom: no hash, no version
			name:    "local scenario",
			files:   []hubFile{localScenario, tainted},
			version: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := buildHub(t, tc.files)

			_, err := exprhelpers.LoadMacros(hub)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := exprhelpers.LoadMacros(nil)
				require.NoError(t, err)
			})

			factories, _, err := LoadBuckets(&csconfig.CrowdsecServiceCfg{}, hub, hub.GetInstalledByType(cwhub.SCENARIOS, true), false)
			require.NoError(t, err)
			require.Len(t, factories, 1)
			require.Equal(t, tc.version, factories[0].Spec.ScenarioVersion)
		})
	}
}

func TestBucketSpecExpressions(t *testing.T) {
	// string fields of BucketSpec that are not expressions
	notExpressions := []string{"FormatVersion", "Description", "Type", "Name", "LeakSpeed", "Blackhole", "Duration", "ScenarioVersion"}

	spec := BucketSpec{}
	v := reflect.ValueOf(&spec).Elem()

	var expected []string

	for i := range v.NumField() {
		field := v.Type().Field(i)
		if field.Type.Kind() != reflect.String || slices.Contains(notExpressions, field.Name) {
			continue
		}

		v.Field(i).SetString(field.Name)
		expected = append(expected, field.Name)
	}

	spec.ScopeType.Filter = "ScopeType.Filter"
	spec.BayesianConditions = []RawBayesianCondition{{ConditionalFilterName: "BayesianConditions"}}
	expected = append(expected, "ScopeType.Filter", "BayesianConditions")

	require.ElementsMatch(t, expected, spec.expressions(), "classify new BucketSpec fields in expressions() or notExpressions")
}
