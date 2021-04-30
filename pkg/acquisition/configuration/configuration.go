package configuration

import (
	log "github.com/sirupsen/logrus"
)

type DataSourceCommonCfg struct {
	Mode       string            `yaml:"mode,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty"`
	LogLevel   *log.Level        `yaml:"log_level,omitempty"`
	Type       string            `yaml:"type,omitempty"`
	ConfigFile string            `yaml:"-"` //filled at run time : the filepath from which the config was unmarshaled
	//logger     *log.Entry        `yaml:"-"`
}

func (d *DataSourceCommonCfg) SetDefaults() error {
	// default mode is tail
	if d.Mode == "" {
		d.Mode = TAIL_MODE
	}
	return nil
}

var TAIL_MODE = "tail"
var CAT_MODE = "cat"
var SERVER_MODE = "server" // No difference with tail, just a bit more verbose
