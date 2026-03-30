package logging

import (
	"cmp"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	defLogLevel    = logrus.InfoLevel
	defLogFilename = "crowdsec.log"
)

// SetupStandardLogger configures the global logger according to the
// provided configuration. It applies the output destination, log format,
// rotation policy, and log level used by all components that rely on the
// default logrus instance (`logrus.StandardLogger()`).
func SetupStandardLogger(cfg LogConfig, level logrus.Level, forceColors bool) error {
	var logFormatter logrus.Formatter

	switch cfg.GetMedia() {
	case "file":
		logrus.SetOutput(cfg.NewRotatingLogger(defLogFilename))
	case "syslog":
		if err := setupSyslogDefault(); err != nil {
			return err
		}
	case "stdout":
		// noop
	default:
		return fmt.Errorf("unknown log_mode %q", cfg.GetMedia())
	}

	logrus.SetLevel(cmp.Or(level, defLogLevel))

	switch cfg.GetFormat() {
	case "text", "":
		logFormatter = &logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			ForceColors:     forceColors,
		}
	case "json":
		logFormatter = &logrus.JSONFormatter{TimestampFormat: time.RFC3339}
	default:
		return fmt.Errorf("unknown log_format %q", cfg.GetFormat())
	}

	logrus.SetFormatter(logFormatter)

	return nil
}
