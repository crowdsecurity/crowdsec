package csconfig

import log "github.com/sirupsen/logrus"

/*daemonization/service related stuff*/
type CommonCfg struct {
	Daemonize  bool
	PidDir     string     `yaml:"pid_dir"`
	LogMedia   string     `yaml:"log_media"`
	LogDir     string     `yaml:"log_dir,omitempty"` //if LogMedia = file
	LogLevel   *log.Level `yaml:"log_level"`
	WorkingDir string     `yaml:"working_dir,omitempty"` ///var/run
}
