package logging

import (
	"cmp"
	"fmt"
	"io"
	"log/syslog"
	"path/filepath"
	"time"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

const (
	defMaxSize = 500
	defMaxFiles = 3
	defMaxAge = 28
	defCompress = true
	defLogLevel = log.InfoLevel
)

func SetupDefaultLogger(cfg csconfig.CommonLogConfig) error {
	var logFormatter log.Formatter

	switch cfg.LogFormat {
	case "text", "":
		logFormatter = &log.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			ForceColors:     cfg.ForceColorLogs,
		}
	case "json":
		logFormatter = &log.JSONFormatter{TimestampFormat: time.RFC3339}
	default:
		return fmt.Errorf("unknown log_format '%s'", cfg.LogFormat)
	}

	if cfg.LogMedia == "file" {
		logOutput := &lumberjack.Logger{
			Filename:   filepath.Join(cfg.LogDir, "crowdsec.log"),
			MaxSize:    cmp.Or(cfg.LogMaxSize, defMaxSize),
			MaxBackups: cmp.Or(cfg.LogMaxFiles, defMaxFiles),
			MaxAge:     cmp.Or(cfg.LogMaxAge, defMaxAge),
			Compress:   *cmp.Or(cfg.CompressLogs, ptr.Of(defCompress)),
		}
		log.SetOutput(logOutput)
	} else if cfg.LogMedia == "syslog" {
		w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "crowdsec")
		if err != nil {
			return err
		}

		hook := NewFormatterSyslogHook(w)
		log.AddHook(hook)
		log.SetOutput(io.Discard)
	} else if cfg.LogMedia != "stdout" {
		return fmt.Errorf("log mode %q unknown", cfg.LogMedia)
	}

	log.SetLevel(cmp.Or(cfg.LogLevel, defLogLevel))
	log.SetFormatter(logFormatter)

	return nil
}
