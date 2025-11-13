package logging

import (
	"errors"
)

func setupSyslogDefault() error {
	return errors.New(`log_media="syslog" is not supported on windows`)
}
