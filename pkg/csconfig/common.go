package csconfig

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

/*daemonization/service related stuff*/
type CommonCfg struct {
	Daemonize  bool
	PidDir     string     `yaml:"pid_dir"`
	LogMedia   string     `yaml:"log_media"`
	LogDir     string     `yaml:"log_dir,omitempty"` //if LogMedia = file
	LogLevel   *log.Level `yaml:"log_level"`
	WorkingDir string     `yaml:"working_dir,omitempty"` ///var/run
}

func (c *Config) LoadCommon() error {
	var err error
	if c.Common == nil {
		return fmt.Errorf("no common block provided in configuration file")
	}

	var CommonCleanup = []*string{
		&c.Common.PidDir,
		&c.Common.LogDir,
		&c.Common.WorkingDir,
	}
	for _, k := range CommonCleanup {
		if *k == "" {
			continue
		}
		*k, err = filepath.Abs(*k)
		if err != nil {
			return errors.Wrap(err, "failed to clean path")
		}
	}

	return nil
}
