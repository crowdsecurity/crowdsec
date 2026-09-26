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

func TestConfigureInvalidTailMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.log")

	s := Source{}
	err := s.Configure(
		t.Context(),
		[]byte(fmt.Sprintf(`
mode: tail
filenames:
 - %s
tail_mode: invalid
`, testFile)),
		log.WithField("type", ModuleName),
		metrics.AcquisitionMetricsLevelNone,
	)
	require.ErrorContains(t, err, "unsupported tail_mode")
}

func TestUnmarshalConfigStatPollIntervalZeroDefaultsToTwoSeconds(t *testing.T) {
	t.Parallel()

	s := Source{}
	err := s.UnmarshalConfig([]byte(`
mode: tail
filenames:
 - /tmp/example.log
tail_mode: stat
`))
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, s.config.StatPollInterval)
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

func TestKeepFileOpenForTailMode(t *testing.T) {
	t.Parallel()

	require.True(t, keepFileOpenForTailMode("default"))
	require.False(t, keepFileOpenForTailMode("stat"))
}

func TestConfigureTailModeStored(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		configSnippet  string
		wantTailMode   string
		wantKeepOpen   bool
		wantPollPeriod time.Duration
	}{
		{
			name:           "default",
			configSnippet:  "",
			wantTailMode:   "default",
			wantKeepOpen:   true,
			wantPollPeriod: 0,
		},
		{
			name: "stat",
			configSnippet: `
tail_mode: stat
stat_poll_interval: 100ms`,
			wantTailMode:   "stat",
			wantKeepOpen:   false,
			wantPollPeriod: 100 * time.Millisecond,
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
mode: tail
filenames:
 - %s%s
`, testFile, tc.configSnippet)),
				log.WithField("type", ModuleName),
				metrics.AcquisitionMetricsLevelNone,
			)
			require.NoError(t, err)
			require.Equal(t, tc.wantTailMode, s.config.TailMode)
			require.Equal(t, tc.wantKeepOpen, keepFileOpenForTailMode(s.config.TailMode))
			if tc.wantPollPeriod != 0 {
				require.Equal(t, tc.wantPollPeriod, s.config.StatPollInterval)
			}
		})
	}
}
