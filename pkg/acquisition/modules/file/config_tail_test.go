package fileacquisition

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

// Configure rejects an unknown mode.
func TestConfigureInvalidMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.log")

	s := Source{}
	err := s.Configure(
		t.Context(),
		[]byte(fmt.Sprintf(`
mode: sideways
filenames:
 - %s
`, testFile)),
		log.WithField("type", ModuleName),
		metrics.AcquisitionMetricsLevelNone,
	)
	require.ErrorContains(t, err, "unsupported mode")
}

// An omitted polltail read interval is stored as two seconds (default value)
func TestUnmarshalConfigPollTailReadIntervalZeroDefaultsToTwoSeconds(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`
mode: polltail
filenames:
 - /tmp/example.log
`))
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, s.config.PollTailReadInterval)
}

// A config with no file path is rejected.
func TestUnmarshalConfigRejectsEmptyFilenames(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`mode: tail`))
	require.ErrorContains(t, err, "no filename or filenames")
}

// An exclude regexp that does not compile is rejected.
func TestUnmarshalConfigRejectsBadExcludeRegexp(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`
mode: tail
filenames:
 - /tmp/example.log
exclude_regexps:
 - "("
`))
	require.ErrorContains(t, err, "could not compile regexp")
}

// Configure stores polltail and the read interval that was set.
func TestConfigureModeStored(t *testing.T) {
	t.Parallel()

	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	s := Source{}
	err := s.Configure(
		t.Context(),
		[]byte(fmt.Sprintf(`
mode: polltail
filenames:
 - %s
polltail_read_interval: 100ms
`, testFile)),
		log.WithField("type", ModuleName),
		metrics.AcquisitionMetricsLevelNone,
	)
	require.NoError(t, err)
	require.Equal(t, configuration.POLLTAIL_MODE, s.config.Mode)
	require.Equal(t, 100*time.Millisecond, s.config.PollTailReadInterval)
}
