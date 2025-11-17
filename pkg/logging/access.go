package logging

import (
	"cmp"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// CreateAccessLogger builds and returns a logger configured for HTTP access
// logging using the provided log configuration, level and filename (only for media="file").
//
// If log_media is "file", the access log is written to a fixed filename
// "crowdsec_api.log" inside LogDir. For "stdout" or "syslog", the access
// logger uses the same output destination as the standard logger.
func CreateAccessLogger(cfg csconfig.LogConfig, level logrus.Level, filename string) *logrus.Logger {
	clog := CloneLogger(logrus.StandardLogger(), level)

	if cfg.LogMedia != "file" {
		return clog
	}

	logFile := filepath.Join(cfg.LogDir, filename)
	logrus.Debugf("starting router, logging to %s", logFile)

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    cmp.Or(cfg.LogMaxSize, defMaxSize),
		MaxBackups: cmp.Or(cfg.LogMaxFiles, defMaxFiles),
		MaxAge:     cmp.Or(cfg.LogMaxAge, defMaxAge),
		Compress:   *cmp.Or(cfg.CompressLogs, ptr.Of(defCompress)),
	}

	clog.SetOutput(logger)

	return clog
}
