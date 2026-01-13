package acquisition

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/goccy/go-yaml"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

var (
	wantErrLineRE = regexp.MustCompile(`(?m)^\s*#\s*wantErr:\s*(.*?)\s*$`)
	wantSchemaErrLineRE = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*schemaErr:[ \t]*([^\r\n]*)[ \t]*$`)
)

func findYAMLFiles(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	require.NoError(t, err, "walking %q", root)

	slices.Sort(files)
	return files
}

func wantErrFromYAML(t *testing.T, fileContent []byte) (want string, found bool) {
	t.Helper()

	m := wantErrLineRE.FindSubmatch(fileContent)
	if len(m) == 0 {
		return "", false
	}

	return strings.TrimSpace(string(m[1])), true
}

func wantSchemaErrFromYAML(t *testing.T, fileContent []byte) (want string, found bool) {
	t.Helper()

	m := wantSchemaErrLineRE.FindSubmatch(fileContent)
	if len(m) == 0 {
		return "", false
	}

	return strings.TrimSpace(string(m[1])), true
}

func TestParseSourceConfig(t *testing.T) {
	ctx := t.Context()

	type suite struct {
		name        string
		root        string
		expectValid bool
	}

	type source struct {
		Source string
	}

	// load a configuration, appsec needs it
	_, _, err := csconfig.NewConfig("./testdata/config.yaml", false, false, true)
	require.NoError(t, err)

	// load a hub, appsec needs it
	hub := cwhub.Hub{}

	suites := []suite{
		{name: "valid", root: filepath.Join("testdata", "valid"), expectValid: true},
		{name: "invalid", root: filepath.Join("testdata", "invalid"), expectValid: false},
	}

	for _, s := range suites {
		t.Run(s.name, func(t *testing.T) {
			files := findYAMLFiles(t, s.root)
			require.NotEmpty(t, files, "no YAML files found under %q", s.root)

			for _, path := range files {
				rel, _ := filepath.Rel(s.root, path)

				fileContent, err := os.ReadFile(path)
				require.NoError(t, err, "read %q", path)

				t.Run(filepath.ToSlash(rel), func(t *testing.T) {
					var (
						so source
						schema string
					)

					if err = yaml.Unmarshal(fileContent, &so); err == nil {
						schema = filepath.Join("schemas", so.Source + ".yaml")
					}

					if runtime.GOOS == "windows" && strings.Contains(path, "journalctl") {
						return
					}

					if runtime.GOOS != "windows" && strings.Contains(path, "wineventlog") {
						return
					}

					wantErr, hasWant := wantErrFromYAML(t, fileContent)

					wantSchemaErr, hasWantSchemaErr := wantSchemaErrFromYAML(t, fileContent)

					if s.expectValid {
						require.False(t, hasWant, "valid config must not include # wantErr: directive")
						parsed, err := ParseSourceConfig(ctx, fileContent, metrics.AcquisitionMetricsLevelNone, &hub)
						require.NoError(t, err)
						require.NotNil(t, parsed)
						if schema != "" {
							err = ValidateYAML(fileContent, schema)
							if !errors.Is(err, fs.ErrNotExist) {
								// XXX: ignore missing schema
								require.NoError(t, err)
							}
						}
						return
					}

					// invalid

					require.True(t, hasWant, "invalid config must include '# wantErr: <exact error>'")
					require.NotEmpty(t, wantErr, "wantErr directive found but empty")

					parsed, err := ParseSourceConfig(ctx, fileContent, metrics.AcquisitionMetricsLevelNone, &hub)
					require.Error(t, err, "got no error, expected %q", wantErr)
					require.Nil(t, parsed)
					assert.Equal(t, wantErr, err.Error())
					if schema == "" {
						return
					}

					// schema validation

					err = ValidateYAML(fileContent, schema)
					if errors.Is(err, fs.ErrNotExist) {
						// XXX: ignore missing schema, for now
						return
					}

					// a "schemaErr" comment must be present, even if empty
					require.True(t, hasWantSchemaErr, "invalid configurations require an exlicit schemaErr comment. it can be empty string if the schema cannot detect the issue")
					switch {
					case err == nil && wantSchemaErr != "":
						require.Error(t, err, "got no schema error, expected %q", wantSchemaErr)
					case err != nil && wantSchemaErr == "":
						require.Error(t, err, "got schema error %q, expected nil", err)
					case err != nil:
						assert.Contains(t, err.Error(), wantSchemaErr)
					default:
						require.NoError(t, err)
						assert.Empty(t, wantSchemaErr)
					}
				})
			}
		})
	}
}
