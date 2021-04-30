package configuration

import (
	log "github.com/sirupsen/logrus"
)

type DataSourceCommonCfg struct {
	Mode     string            `yaml:"mode,omitempty"`
	Labels   map[string]string `yaml:"labels,omitempty"`
	LogLevel *log.Level        `yaml:"log_level,omitempty"`
	Source   string            `yaml:"source,omitempty"`
}

var TAIL_MODE = "tail"
var CAT_MODE = "cat"
var SERVER_MODE = "server" // No difference with tail, just a bit more verbose
