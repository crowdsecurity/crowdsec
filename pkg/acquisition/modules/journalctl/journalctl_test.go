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
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// readTimeout is only ever reached when a line never arrives: it's generous on
// purpose, so that a slow machine doesn't turn into a test failure.
const readTimeout = 10 * time.Second

// quietPeriod is how long we wait to confirm that no extra line shows up. Kept
// short on purpose: a line slower than this is missed, which is better than
// failing at random on a loaded machine.
const quietPeriod = 100 * time.Millisecond

func TestConfigureDSN(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		dsn     string
		wantErr string
	}{
		{
			dsn:     "asd://",
			wantErr: "invalid DSN asd:// for journalctl source, must start with journalctl://",
		},
		{
			dsn:     "journalctl://",
			wantErr: "empty journalctl:// DSN",
		},
		{
			dsn:     "journalctl://foobar=42",
			wantErr: "unsupported key foobar in journalctl DSN",
		},
		{
			dsn:     "journalctl://filters=%ZZ",
			wantErr: "could not parse journalctl DSN: invalid URL escape \"%ZZ\"",
		},
		{
			dsn: "journalctl://filters=_UID=42?log_level=warn",
		},
		{
			dsn:     "journalctl://filters=_UID=1000&log_level=foobar",
			wantErr: `not a valid logrus Level: "foobar"`,
		},
		{
			dsn: "journalctl://filters=_UID=1000&log_level=warn&since=yesterday",
		},
	}

	for _, tc := range tests {
		t.Run(tc.dsn, func(t *testing.T) {
			f := Source{}
			logger, _ := logtest.NewNullLogger()
			err := f.ConfigureByDSN(ctx, tc.dsn, map[string]string{"type": "testtype"}, logrus.NewEntry(logger), "")
			cstest.RequireErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestOneShot(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		config    string
		wantErr   string
		wantLines int
		wantLog   []string
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - "-_UID=42"`,
			wantErr: "exit status 1",
			wantLog: []string{
				"Got stderr: journalctl: invalid option -- '_'",
			},
			wantLines: 0,
		},
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			wantLines: 14,
		},
	}
	for _, ts := range tests {
		t.Run(ts.config, func(t *testing.T) {
			out := make(chan pipeline.Event, 100)
			j := Source{}

			logger, hook := logtest.NewNullLogger()

			err := j.Configure(ctx, []byte(ts.config), logrus.NewEntry(logger), metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			err = j.OneShot(ctx, out)
			cstest.RequireErrorContains(t, err, ts.wantErr)

			for _, wantMessage := range ts.wantLog {
				cstest.RequireLogContains(t, hook, wantMessage)
			}

			if ts.wantErr != "" {
				return
			}

			assert.Len(t, out, ts.wantLines)
		})
	}
}

func TestStreaming(t *testing.T) {
	cstest.SkipOnWindows(t)

	ctx := t.Context()

	tests := []struct {
		config    string
		wantErr   string
		wantLines int
	}{
		{
			config: `
source: journalctl
mode: cat
journalctl_filter:
 - _SYSTEMD_UNIT=ssh.service`,
			wantLines: 14,
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

			var (
				wg         sync.WaitGroup
				extraLines int
			)

			if ts.wantLines != 0 {
				wg.Go(func() {
					// whatever happens below, the stream has to be stopped or
					// j.Stream() would never return
					defer cancel()

					// consuming every line lets journalctl exit on its own
					for i := range ts.wantLines {
						select {
						case <-out:
						case <-time.After(readTimeout):
							t.Errorf("timed out waiting for line %d/%d", i+1, ts.wantLines)
							return
						}
					}

					// keep draining for a moment: it catches extra lines, and it keeps a
					// source that sends too many from deadlocking on the unbuffered
					// channel instead of failing the test
					for {
						select {
						case <-out:
							extraLines++
						case <-time.After(quietPeriod):
							return
						}
					}
				})
			}

			err = j.Stream(ctx, out)
			cstest.RequireErrorContains(t, err, ts.wantErr)

			if ts.wantErr != "" {
				cancel()
				return
			}

			if ts.wantLines != 0 {
				wg.Wait()
				assert.Zero(t, extraLines, "source emitted more lines than expected")
			}

			cancel()

			// not the ctx above: it's cancelled by now, which would make pgrep
			// return nothing and the check below always pass
			output, _ := exec.CommandContext(t.Context(), "pgrep", "-x", "journalctl").CombinedOutput()
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
