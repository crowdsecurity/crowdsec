package main

import (
	"io"

	log "github.com/sirupsen/logrus"
)

// FatalHook is used to log fatal messages to stderr when the rest goes to a file
type FatalHook struct {
	Writer    io.Writer
	LogLevels []log.Level
}

func (hook *FatalHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	_, err = hook.Writer.Write([]byte(line))

	return err
}

func (hook *FatalHook) Levels() []log.Level {
	return hook.LogLevels
}
