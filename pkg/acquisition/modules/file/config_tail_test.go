package fileacquisition

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

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

func TestUnmarshalConfigRejectsEmptyFilenames(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`mode: tail`))
	require.ErrorContains(t, err, "no filename or filenames")
}

func TestUnmarshalConfigRejectsUnsupportedMode(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`
mode: no-such-mode
filenames:
 - /tmp/example.log
`))
	require.ErrorContains(t, err, "unsupported mode")
}

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

func TestConfigureModeStored(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		mode           string
		extra          string
		wantReadPeriod time.Duration
	}{
		{name: "tail", mode: "tail"},
		{
			name:           "polltail",
			mode:           "polltail",
			extra:          "\npolltail_read_interval: 100ms",
			wantReadPeriod: 100 * time.Millisecond,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testFile := filepath.Join(t.TempDir(), "test.log")
			require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

			s := Source{}
			err := s.Configure(
				t.Context(),
				[]byte(fmt.Sprintf(`
mode: %s
filenames:
 - %s%s
`, tc.mode, testFile, tc.extra)),
				log.WithField("type", ModuleName),
				metrics.AcquisitionMetricsLevelNone,
			)
			require.NoError(t, err)
			require.Equal(t, tc.mode, s.config.Mode)
			if tc.wantReadPeriod != 0 {
				require.Equal(t, tc.wantReadPeriod, s.config.PollTailReadInterval)
			}
		})
	}
}
