package types

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logFormatter log.Formatter
var LogOutput *lumberjack.Logger //io.Writer
var logLevel log.Level

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, LogFormat string, compress *bool, forceColors bool) error {

	// Set text as default formatter if log_format: text is configured or log_format: ""
	logFormatter = &log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true, ForceColors: forceColors}
	
	/*Configure logs*/
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
		
		if LogFormat == "json" {
			logFormatter = &log.JSONFormatter{TimestampFormat: time.RFC3339}
		} else if LogFormat == "" {
			log.Warn("no log_format configured default to 'text' format")
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
	log.SetLevel(logLevel)

	log.SetFormatter(logFormatter)
	return nil
}

func ConfigureLogger(clog *log.Logger) error {
	/*Configure logs*/
	if LogOutput != nil {
		clog.SetOutput(LogOutput)
	}

	if logFormatter != nil {
		clog.SetFormatter(logFormatter)
	}
	clog.SetLevel(logLevel)
	return nil
}

func UtcNow() time.Time {
	return time.Now().UTC()
}

func IsNetworkFS(path string) (bool, string, error) {
	fsType, err := GetFSType(path)
	if err != nil {
		return false, "", err
	}
	fsType = strings.ToLower(fsType)
	return fsType == "nfs" || fsType == "cifs" || fsType == "smb" || fsType == "smb2", fsType, nil
}
