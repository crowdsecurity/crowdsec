//go:build !windows

package logging

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/natefinch/lumberjack.v2"
)

type testLogConfig struct {
	media string
	dir   string
}

func (c testLogConfig) GetMedia() string { return c.media }
func (testLogConfig) GetFormat() string  { return "text" }

func (c testLogConfig) NewRotatingLogger(filename string) *lumberjack.Logger {
	return &lumberjack.Logger{Filename: filepath.Join(c.dir, filename)}
}

func TestSetupStandardLoggerReloadFromSyslog(t *testing.T) {
	tests := []struct {
		name      string
		media     string
		wantHooks int
		wantOut   func(t *testing.T, out io.Writer)
	}{
		{
			name:      "syslog",
			media:     "syslog",
			wantHooks: 1,
			wantOut: func(t *testing.T, out io.Writer) {
				require.Equal(t, io.Discard, out)
			},
		},
		{
			name:      "file",
			media:     "file",
			wantHooks: 0,
			wantOut: func(t *testing.T, out io.Writer) {
				require.IsType(t, &lumberjack.Logger{}, out)
			},
		},
		{
			name:      "stdout",
			media:     "stdout",
			wantHooks: 0,
			wantOut: func(t *testing.T, out io.Writer) {
				require.Equal(t, os.Stderr, out)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.StandardLogger()
			hooks := logger.ReplaceHooks(make(logrus.LevelHooks))
			out := logger.Out

			t.Cleanup(func() {
				logger.ReplaceHooks(hooks)
				logger.SetOutput(out)
			})

			// state left by a first config load with log_media: syslog,
			// without needing a syslog daemon
			logger.AddHook(NewFormatterSyslogHook(nil))
			logger.SetOutput(io.Discard)

			cfg := testLogConfig{media: tc.media, dir: t.TempDir()}

			// each SIGHUP reloads the config
			for range 3 {
				require.NoError(t, SetupStandardLogger(cfg, logrus.InfoLevel, false))
			}

			for _, lvl := range logrus.AllLevels {
				require.Len(t, logger.Hooks[lvl], tc.wantHooks, "level %s", lvl)
			}

			tc.wantOut(t, logger.Out)
		})
	}
}
