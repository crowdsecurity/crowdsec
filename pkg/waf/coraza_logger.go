package waf

import (
	"fmt"
	"io"

	dbg "github.com/crowdsecurity/coraza/v3/debuglog"
	log "github.com/sirupsen/logrus"
)

var DebugRules map[int]bool = map[int]bool{}

func SetRuleDebug(id int, debug bool) {
	DebugRules[id] = debug
}

func GetRuleDebug(id int) bool {
	if val, ok := DebugRules[id]; ok {
		return val
	}
	return false
}

// type ContextField func(Event) Event

type crzLogEvent struct {
	fields log.Fields
	logger *log.Entry
	muted  bool
}

func (e *crzLogEvent) Msg(msg string) {
	if e.muted {
		return
	}
	if len(e.fields) == 0 {
		e.logger.Info(msg)
	} else {
		e.logger.WithFields(e.fields).Info(msg)
	}
}

func (e *crzLogEvent) Str(key, val string) dbg.Event {
	if e.muted {
		return e
	}
	//e.logger.Info("str")
	e.fields[key] = val
	return e
}

func (e *crzLogEvent) Err(err error) dbg.Event {
	if e.muted {
		return e
	}
	//e.logger.Info("err")
	e.fields["error"] = err
	return e
}

func (e *crzLogEvent) Bool(key string, b bool) dbg.Event {
	if e.muted {
		return e
	}
	//e.logger.Info("bool")
	e.fields[key] = b
	return e
}

func (e *crzLogEvent) Int(key string, i int) dbg.Event {
	if e.muted {
		if key == "rule_id" {
			log.Warningf("is rule_id %d in debug mode -> %t", i, GetRuleDebug(i))
			if GetRuleDebug(i) {
				e.muted = false
				e.fields = map[string]interface{}{}
			} else {
				return e
			}
		}
	}
	//e.logger.Info("int")
	e.fields[key] = i
	return e
}

func (e *crzLogEvent) Uint(key string, i uint) dbg.Event {
	if e.muted {
		return e
	}
	//e.logger.Info("uint")
	e.fields[key] = i
	return e
}

func (e *crzLogEvent) Stringer(key string, val fmt.Stringer) dbg.Event {
	if e.muted {
		return e
	}
	//e.logger.Info("stringer")
	e.fields[key] = val
	return e
}

func (e crzLogEvent) IsEnabled() bool {
	if e.muted {
		return false
	}
	return true
}

type crzLogger struct {
	logger        *log.Entry
	defaultFields log.Fields
	logLevel      log.Level
}

func NewCrzLogger(logger *log.Entry) crzLogger {
	return crzLogger{logger: logger, logLevel: logger.Logger.GetLevel()}
}

func (c crzLogger) WithOutput(w io.Writer) dbg.Logger {
	c.logger.Infof("ignoring withoutput directive")
	return c
}

func (c crzLogger) WithLevel(lvl dbg.Level) dbg.Logger {
	c.logger.Warningf("setting log level to %s", lvl)
	c.logLevel = log.Level(lvl)
	c.logger.Logger.SetLevel(c.logLevel)
	return c
}

func (c crzLogger) With(fs ...dbg.ContextField) dbg.Logger {
	var e dbg.Event = &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	for _, f := range fs {
		e = f(e)
	}
	c.defaultFields = e.(*crzLogEvent).fields
	return c
}

func (c crzLogger) Trace() dbg.Event {
	if c.logLevel < log.TraceLevel {
		//c.logger.Infof("ignoring trace directive")
		return &crzLogEvent{muted: true}
	}
	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}

func (c crzLogger) Debug() dbg.Event {
	if c.logLevel < log.DebugLevel {
		//c.logger.Infof("ignoring debug directive -> %s", c.logLevel.String())
		return &crzLogEvent{muted: true, logger: c.logger}

	}

	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}

func (c crzLogger) Info() dbg.Event {
	if c.logLevel < log.InfoLevel {
		return &crzLogEvent{muted: true}
	}
	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}

func (c crzLogger) Warn() dbg.Event {
	if c.logLevel < log.WarnLevel {
		return &crzLogEvent{muted: true}
	}
	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}

func (c crzLogger) Error() dbg.Event {
	if c.logLevel < log.ErrorLevel {
		return &crzLogEvent{muted: true}
	}
	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}
