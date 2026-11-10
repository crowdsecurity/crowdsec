package logging

import (
	"errors"

	"github.com/sirupsen/logrus"
)

func setupSyslogDefault() error {
	return errors.New(`log_media="syslog" is not supported on windows`)
}

func removeSyslogHooks(*logrus.Logger) {}
