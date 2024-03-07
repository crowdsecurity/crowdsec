package main

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

type ConditionalHook struct {
	Writer    io.Writer
	LogLevels []log.Level
	Enabled   bool
}

func (hook *ConditionalHook) Fire(entry *log.Entry) error {
	// don't log if the hook is disabled
	// or if the level is fatal (the standard logger will handle it)
	
	if !hook.Enabled || entry.Level == log.FatalLevel {
		return nil
	}

	line, err := entry.String()
	if err != nil {
		return err
	}

	_, err = hook.Writer.Write([]byte(line))

	return err
}

func (hook *ConditionalHook) Levels() []log.Level {
	return hook.LogLevels
}

// The primal logging hook is set up before parsing config.yaml.
// Once config.yaml is parsed, the primal hook is disabled if the
// configured logger is writing to stderr. Otherwise it's used to
// report fatal errors and panics to stderr in addition to the log file.
var primalHook = &ConditionalHook{
	Writer:    os.Stderr,
	LogLevels: []log.Level{log.FatalLevel, log.PanicLevel},
	Enabled:   true,
}
