package journalctlacquisition

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestBadConfiguration(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd.log`,
			expectedErr: `cannot parse: [1:1] unknown field "foobar"`,
		},
		{
			config: `
mode: tail
source: journalctl`,
			expectedErr: "journalctl_filter is required",
		},
		{
			config: `
mode: cat
source: journalctl
journalctl_filter:
 - _UID=42`,
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.config, func(t *testing.T) {
			f := Source{}
			logger, _ := logtest.NewNullLogger()
			err := f.Configure(ctx, []byte(tc.config), logrus.NewEntry(logger), metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestConfigureDSN(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		dsn         string
		expectedErr string
	}{
		{
			dsn:         "asd://",
			expectedErr: "invalid DSN asd:// for journalctl source, must start with journalctl://",
		},
		{
			dsn:         "journalctl://",
			expectedErr: "empty journalctl:// DSN",
		},
		{
			dsn:         "journalctl://foobar=42",
			expectedErr: "unsupported key foobar in journalctl DSN",
		},
		{
			dsn:         "journalctl://filters=%ZZ",
			expectedErr: "could not parse journalctl DSN: invalid URL escape \"%ZZ\"",
		},
		{
			dsn:         "journalctl://filters=_UID=42?log_level=warn",
			expectedErr: "",
		},
		{
			dsn:         "journalctl://filters=_UID=1000&log_level=foobar",
			expectedErr: `not a valid logrus Level: "foobar"`,
		},
		{
			dsn:         "journalctl://filters=_UID=1000&log_level=warn&since=yesterday",
			expectedErr: "",
		},
	}

	for _, test := range tests {
		f := Source{}
		logger, _ := logtest.NewNullLogger()
		err := f.ConfigureByDSN(ctx, test.dsn, map[string]string{"type": "testtype"}, logrus.NewEntry(logger), "")
		cstest.RequireErrorContains(t, err, test.expectedErr)
	}
}

func TestOneShot(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		config         string
		expectedErr    string
		expectedLines  int
		expectedLog    []string
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - "-_UID=42"`,
			expectedErr:    "exit status 1",
			expectedLog:    []string{
				"Got stderr: journalctl: invalid option -- '_'",
			},
			expectedLines:  0,
		},
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			expectedLines:  14,
		},
	}
	for _, ts := range tests {
		out := make(chan pipeline.Event, 100)
		j := Source{}

		logger, hook := logtest.NewNullLogger()

		err := j.Configure(ctx, []byte(ts.config), logrus.NewEntry(logger), metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		err = j.OneShot(ctx, out)
		cstest.RequireErrorContains(t, err, ts.expectedErr)

		for _, expectedMessage := range ts.expectedLog {
			cstest.RequireLogContains(t, hook, expectedMessage)
		}

		if ts.expectedErr != "" {
			continue
		}

		if ts.expectedLines != 0 {
			assert.Len(t, out, ts.expectedLines)
		}
	}
}

func TestStreaming(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		config         string
		expectedErr    string
		expectedLines  int
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			expectedLines:  14,
		},
	}
	for idx, ts := range tests {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			out := make(chan pipeline.Event)
			j := Source{}

			logger, _ := logtest.NewNullLogger()

			err := j.Configure(ctx, []byte(ts.config), logrus.NewEntry(logger), metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			actualLines := 0
			var wg sync.WaitGroup

			if ts.expectedLines != 0 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-out:
							actualLines++
						case <-time.After(1 * time.Second):
							cancel()
							return
						}
					}
				}()
			}

			err = j.Stream(ctx, out)
			cstest.RequireErrorContains(t, err, ts.expectedErr)

			if ts.expectedErr != "" {
				cancel()
				return
			}

			if ts.expectedLines != 0 {
				wg.Wait()
				assert.Equal(t, ts.expectedLines, actualLines)
			}

			cancel()

			output, _ := exec.CommandContext(ctx, "pgrep", "-x", "journalctl").CombinedOutput()
			assert.Empty(t, output, "zombie journalctl process detected!")
		})
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("USE_SYSTEM_JOURNALCTL") == "" {
		fullPath, _ := filepath.Abs("./testdata")
		os.Setenv("PATH", fullPath+":"+os.Getenv("PATH"))
	}

	m.Run()
}
