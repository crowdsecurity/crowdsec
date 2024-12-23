package main

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

// FatalHook is used to log fatal messages to stderr when the rest goes to a file
type FatalHook struct {
	Writer    io.Writer
	Formatter log.Formatter
	LogLevels []log.Level
}

func newFatalHook() *FatalHook {
	return &FatalHook{
		Writer: os.Stderr,
		Formatter: &log.TextFormatter{
			DisableTimestamp: true,
			// XXX: logrus.TextFormatter has either key pairs with no colors,
			// or "LEVEL [optional timestamp] message", with colors.
			// We force colors to make sure we get the latter, even if
			// the output is not a terminal.
			// There are more flexible formatters that don't conflate the two concepts,
			// or we can write our own.
			ForceColors:            true,
			DisableLevelTruncation: true,
		},
		LogLevels: []log.Level{log.FatalLevel, log.PanicLevel},
	}
}

func (hook *FatalHook) Fire(entry *log.Entry) error {
	line, err := hook.Formatter.Format(entry)
	if err != nil {
		return err
	}

	_, err = hook.Writer.Write(line)

	return err
}

func (hook *FatalHook) Levels() []log.Level {
	return hook.LogLevels
}
