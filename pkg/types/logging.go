package types

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/cslog"
	"github.com/crowdsecurity/go-cs-lib/cstty"
)

var logFormatter log.Formatter
var LogOutput *lumberjack.Logger //io.Writer
var logLevel log.Level

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, compress *bool, forceColors bool) error {
	clearline := false

	switch cfgMode {
	case "file":
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
	case "stdout":
		if cstty.IsTTY(os.Stderr.Fd()) {
			clearline = true
		}
	default:
		return fmt.Errorf("log mode '%s' unknown", cfgMode)
	}

	if clearline {
		logFormatter = &cslog.ClearLineFormatter{TextFormatter: log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true, ForceColors: forceColors}}
	} else {
		logFormatter = &log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true, ForceColors: forceColors}
	}

	// XXX: set logLevel for the other loggers (papi & co)
	logLevel = cfgLevel
	log.SetLevel(logLevel)
	log.SetFormatter(logFormatter)

	return nil
}

func ConfigureLogger(clog *log.Logger) error {
	if LogOutput != nil {
		clog.SetOutput(LogOutput)
	}

	if logFormatter != nil {
		clog.SetFormatter(logFormatter)
	}
	clog.SetLevel(logLevel)
	return nil
}
