package types

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logFormatter log.Formatter
var LogOutput *lumberjack.Logger //io.Writer
var logLevel log.Level

func SetDefaultLoggerConfig(cfgMode string, cfgFolder string, cfgLevel log.Level, maxSize int, maxFiles int, maxAge int, compress *bool, forceColors bool) error {
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
	logFormatter = &log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true, ForceColors: forceColors}
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

func ParseDuration(d string) (time.Duration, error) {
	durationStr := d
	if strings.HasSuffix(d, "d") {
		days := strings.Split(d, "d")[0]
		if len(days) == 0 {
			return 0, fmt.Errorf("'%s' can't be parsed as duration", d)
		}
		daysInt, err := strconv.Atoi(days)
		if err != nil {
			return 0, err
		}
		durationStr = strconv.Itoa(daysInt*24) + "h"
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

func UtcNow() time.Time {
	return time.Now().UTC()
}

func GetLineCountForFile(filepath string) int {
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("unable to open log file %s : %s", filepath, err)
	}
	defer f.Close()
	lc := 0
	fs := bufio.NewScanner(f)
	for fs.Scan() {
		lc++
	}
	return lc
}
