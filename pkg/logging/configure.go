package logging

import (
	"fmt"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	logFormatter    log.Formatter
	LogOutput       *lumberjack.Logger // io.Writer
	logLevel        log.Level
	logLevelViaFlag bool
)

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, format string, compress *bool, forceColors bool, levelViaFlag bool) error {
	if format == "" {
		format = "text"
	}

	switch format {
	case "text":
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
		_maxsize := 500
		if maxSize != 0 {
			_maxsize = maxSize
		}

		_maxfiles := 3
		if maxFiles != 0 {
			_maxfiles = maxFiles
		}

		_maxage := 28
		if maxAge != 0 {
			_maxage = maxAge
		}

		_compress := true
		if compress != nil {
			_compress = *compress
		}

		LogOutput = &lumberjack.Logger{
			Filename:   filepath.Join(cfgFolder, "crowdsec.log"),
			MaxSize:    _maxsize,
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,
			Compress:   _compress,
		}
		log.SetOutput(LogOutput)
	} else if cfgMode != "stdout" {
		return fmt.Errorf("log mode '%s' unknown", cfgMode)
	}

	logLevel = cfgLevel
	logLevelViaFlag = levelViaFlag
	log.SetLevel(logLevel)
	log.SetFormatter(logFormatter)

	return nil
}

func ConfigureLogger(clog *log.Logger, level log.Level) error {
	/*Configure logs*/
	if LogOutput != nil {
		clog.SetOutput(LogOutput)
	}

	if logFormatter != nil {
		clog.SetFormatter(logFormatter)
	}

	clog.SetLevel(logLevel)

	if level != log.PanicLevel && !logLevelViaFlag {
		clog.SetLevel(level)
	}

	return nil
}
