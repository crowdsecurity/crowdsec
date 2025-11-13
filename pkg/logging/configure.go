package logging

import (
	"fmt"
	"io"
	"log/syslog"
	"path/filepath"
	"time"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	defMaxSize = 500
	defMaxFiles = 3
	defMaxAge = 28
	defCompress = true
)

func SetupDefaultLogger(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, format string, compress *bool, forceColors bool) error {
	var logFormatter log.Formatter

	switch format {
	case "text", "":
		logFormatter = &log.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			ForceColors:     forceColors,
		}
	case "json":
		logFormatter = &log.JSONFormatter{TimestampFormat: time.RFC3339}
	default:
		return fmt.Errorf("unknown log_format '%s'", format)
	}

	if cfgMode == "file" {
		if maxSize == 0 {
			maxSize = defMaxSize
		}

		if maxFiles == 0 {
			maxFiles = defMaxFiles
		}

		if maxAge == 0 {
			maxAge = defMaxAge
		}

		if compress == nil {
			compress = ptr.Of(defCompress)
		}

		logOutput := &lumberjack.Logger{
			Filename:   filepath.Join(cfgFolder, "crowdsec.log"),
			MaxSize:    maxSize,
			MaxBackups: maxFiles,
			MaxAge:     maxAge,
			Compress:   *compress,
		}
		log.SetOutput(logOutput)
	} else if cfgMode == "syslog" {
		w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "crowdsec")
		if err != nil {
			return err
		}

		hook := NewFormatterSyslogHook(w)
		log.AddHook(hook)
		log.SetOutput(io.Discard)
	} else if cfgMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", cfgMode)
	}

	if cfgLevel == 0 {
		cfgLevel = log.InfoLevel
	}

	log.SetLevel(cfgLevel)
	log.SetFormatter(logFormatter)

	return nil
}
