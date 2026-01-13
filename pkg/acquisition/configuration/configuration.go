package configuration

import (
	log "github.com/sirupsen/logrus"
)

type DataSourceCommonCfg struct {
	Mode           string            `yaml:"mode,omitempty"`
	Labels         map[string]string `yaml:"labels,omitempty"`
	LogLevel       log.Level         `yaml:"log_level,omitempty"`
	Source         string            `yaml:"source,omitempty"`
	Name           string            `yaml:"name,omitempty"`
	UseTimeMachine bool              `yaml:"use_time_machine,omitempty"`
	UniqueId       string            `yaml:"unique_id,omitempty"`
	TransformExpr  string            `yaml:"transform,omitempty"`
}

const (
	TAIL_MODE   = "tail"
	CAT_MODE    = "cat"
	SERVER_MODE = "server" // No difference with tail, just a bit more verbose
	// XXX:
)
