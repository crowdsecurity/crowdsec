package csconfig

import (
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

/*daemonization/service related stuff*/
type CommonCfg struct {
	Daemonize      bool
	PidDir         string     `yaml:"pid_dir,omitempty"` // TODO: This is just for backward compat. Remove this later
	LogMedia       string     `yaml:"log_media"`
	LogDir         string     `yaml:"log_dir,omitempty"` //if LogMedia = file
	LogLevel       *log.Level `yaml:"log_level"`
	WorkingDir     string     `yaml:"working_dir,omitempty"` // TODO: This is just for backward compat. Remove this later
	CompressLogs   *bool      `yaml:"compress_logs,omitempty"`
	LogMaxSize     int        `yaml:"log_max_size,omitempty"`
	LogMaxAge      int        `yaml:"log_max_age,omitempty"`
	LogMaxFiles    int        `yaml:"log_max_files,omitempty"`
	ForceColorLogs bool       `yaml:"force_color_logs,omitempty"`
}

func (c *Config) loadCommon() error {
	var err error
	if c.Common == nil {
		c.Common = &CommonCfg{}
	}

	if c.Common.LogMedia == "" {
		c.Common.LogMedia = "stdout"
	}

	var CommonCleanup = []*string{
		&c.Common.LogDir,
	}
	for _, k := range CommonCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return fmt.Errorf("failed to get absolute path of '%s': %w", *k, err)
		}
	}

	return nil
}
