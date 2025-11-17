package csconfig

import (
	log "github.com/sirupsen/logrus"
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
