package main

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

type EventLogHook struct {
	LogLevels []log.Level
	evtlog    *eventlog.Log
}

func (e *EventLogHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	switch entry.Level {
	case log.PanicLevel:
		return e.evtlog.Error(300, line)
	case log.FatalLevel:
		return e.evtlog.Error(301, line)
	case log.ErrorLevel:
		return e.evtlog.Error(302, line)
	case log.WarnLevel:
		return e.evtlog.Warning(303, line)
	case log.InfoLevel:
		return e.evtlog.Info(304, line)
	case log.DebugLevel:
		return e.evtlog.Info(305, line)
	case log.TraceLevel:
		return e.evtlog.Info(306, line)
	}
	return nil
}

func (e *EventLogHook) Levels() []log.Level {
	return e.LogLevels
}
