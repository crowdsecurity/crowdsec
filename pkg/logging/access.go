package logging

import (
	"cmp"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

const accessLogFilename = "crowdsec_api.log"

// CreateAccessLogger builds and returns a logger configured for HTTP access
// logging using the fields from LocalApiServerCfg. These fields are derived
// from CommonCfg, except for LogLevel which is specific to the API server.
//
// If log_media is "file", the access log is written to a fixed filename
// "crowdsec_api.log" inside LogDir. For "stdout" or "syslog", the access
// logger uses the same output destination as the standard logger.
func CreateAccessLogger(cfg *csconfig.LocalApiServerCfg) (*logrus.Logger, error) {
	clog := CloneLogger(logrus.StandardLogger(), cfg.LogLevel)

	if cfg.LogMedia != "file" {
		return clog, nil
	}

	logFile := filepath.Join(cfg.LogDir, accessLogFilename)
	logrus.Debugf("starting router, logging to %s", logFile)

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    cmp.Or(cfg.LogMaxSize, defMaxSize),
		MaxBackups: cmp.Or(cfg.LogMaxFiles, defMaxFiles),
		MaxAge:     cmp.Or(cfg.LogMaxAge, defMaxAge),
		Compress:   *cmp.Or(cfg.CompressLogs, ptr.Of(defCompress)),
	}

	clog.SetOutput(logger)

	return clog, nil
}
