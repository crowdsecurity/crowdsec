//go:build !windows

package logging

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type syslogTestConfig struct{ LogConfig }

func (syslogTestConfig) GetMedia() string  { return "syslog" }
func (syslogTestConfig) GetFormat() string { return "text" }

func TestSetupStandardLoggerSyslogReload(t *testing.T) {
	logger := logrus.StandardLogger()
	hooks := logger.ReplaceHooks(make(logrus.LevelHooks))
	out := logger.Out

	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetOutput(out)
	})

	// stands in for the hook from the first config load, so the test doesn't need a syslog daemon
	logger.AddHook(NewFormatterSyslogHook(nil))

	// each SIGHUP reloads the config
	for range 3 {
		require.NoError(t, SetupStandardLogger(syslogTestConfig{}, logrus.InfoLevel, false))
	}

	for _, lvl := range logrus.AllLevels {
		require.Len(t, logger.Hooks[lvl], 1, "level %s", lvl)
	}
}
