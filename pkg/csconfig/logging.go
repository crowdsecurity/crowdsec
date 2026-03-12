package csconfig

import (
	"cmp"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

const (
	defMaxSize  = 500 // megabytes
	defMaxFiles = 3
	defMaxAge   = 28  // days
	defCompress = true
)

// LogConfig contains common fields used to create the default logger, or a service logger when the
// clone/sublogger pattern is not enough, for example access logger to use a different file name.
type LogConfig struct {
	LogMedia       string    `yaml:"log_media"`
	LogDir         string    `yaml:"log_dir,omitempty"` // if LogMedia = file
	CompressLogs   *bool     `yaml:"compress_logs,omitempty"`
	LogMaxSize     int       `yaml:"log_max_size,omitempty"`
	LogFormat      string    `yaml:"log_format,omitempty"`
	LogMaxAge      int       `yaml:"log_max_age,omitempty"`
	LogMaxFiles    int       `yaml:"log_max_files,omitempty"`
}

func (c LogConfig) GetFormat() string {
	return c.LogFormat
}

func (c LogConfig) GetMedia() string {
	return c.LogMedia
}

func (c LogConfig) GetDir() string {
	return c.LogDir
}

func (c LogConfig) NewRotatingLogger(filename string) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   filepath.Join(c.LogDir, filename),
		MaxSize:    cmp.Or(c.LogMaxSize, defMaxSize),
		MaxBackups: cmp.Or(c.LogMaxFiles, defMaxFiles),
		MaxAge:     cmp.Or(c.LogMaxAge, defMaxAge),
		Compress:   *cmp.Or(c.CompressLogs, ptr.Of(defCompress)),
	}
}
