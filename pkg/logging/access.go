package logging

import (
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// CreateAccessLogger builds and returns a logger configured for HTTP access
// logging using the provided log configuration and level.
// If log_media is "file", the access log is written to the provided filename
// inside LogDir. For "stdout" or "syslog", the access logger uses the same
// output destination as the standard logger.
func CreateAccessLogger(cfg LogConfig, level logrus.Level, filename string) *logrus.Logger {
	clog := CloneLogger(logrus.StandardLogger(), level)

	if cfg.GetMedia() != "file" {
		return clog
	}

	logFile := filepath.Join(cfg.GetDir(), filename)
	logrus.Debugf("starting router, logging to %s", logFile)

	clog.SetOutput(cfg.NewRotatingLogger())

	return clog
}
