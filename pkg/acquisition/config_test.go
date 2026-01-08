package acquisition

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

var wantErrLineRE = regexp.MustCompile(`(?m)^\s*#\s*wantErr:\s*(.*?)\s*$`)

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

func TestParseSourceConfig(t *testing.T) {
	ctx := t.Context()

	type suite struct {
		name        string
		root        string
		expectValid bool
	}

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
					wantErr, hasWant := wantErrFromYAML(t, fileContent)

					if s.expectValid {
						require.False(t, hasWant, "valid config must not include # wantErr: directive")
						_, err := ParseSourceConfig(ctx, fileContent, metrics.AcquisitionMetricsLevelNone, nil)
						require.NoError(t, err)
						return
					}

					// invalid
					require.True(t, hasWant, "invalid config must include '# wantErr: <exact error>'")
					require.NotEmpty(t, wantErr, "wantErr directive found but empty")

					_, err := ParseSourceConfig(ctx, fileContent, metrics.AcquisitionMetricsLevelNone, nil)
					require.Error(t, err, "got no error, expected %q", wantErr)
					assert.Equal(t, wantErr, err.Error())
//					assert.Contains(t, err.Error(), wantErr)
				})
			}
		})
	}
}
