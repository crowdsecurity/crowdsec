package csconfig

import (
	log "github.com/sirupsen/logrus"
)

/*daemonization/service related stuff*/
type CommonCfg struct {
	Daemonize      string    // TODO: This is just for backward compat. Remove this later
	PidDir         string    `yaml:"pid_dir,omitempty"` // TODO: This is just for backward compat. Remove this later
	WorkingDir     string    `yaml:"working_dir,omitempty"` // TODO: This is just for backward compat. Remove this later
	ForceColorLogs bool      `yaml:"force_color_logs,omitempty"`
	LogLevel       log.Level `yaml:"log_level"`   // can be overridden by each service
	LogConfig                `yaml:",inline"`
}

func (c *Config) loadCommon() error {
	if c.Common == nil {
		c.Common = &CommonCfg{}
	}

	if c.Common.Daemonize != "" {
		log.Debug("the option 'daemonize' is deprecated and ignored")
	}

	if c.Common.LogMedia == "" {
		c.Common.LogMedia = "stdout"
	}

	return ensureAbsolutePath(&c.Common.LogDir)
}
