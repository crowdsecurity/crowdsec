package appsec

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
	level  log.Level
}

func (e *crzLogEvent) Msg(msg string) {
	if e.muted {
		return
	}

	/*this is a hack. As we want to have per-level rule debug but it's not allowed by coraza/modsec, if a rule ID is flagged to be in debug mode, the
	.Int("rule_id", <ID>) call will set the log_level of the event to debug. However, given the logger is global to the appsec-runner,
	we are switching forth and back the log level of the logger*/
	oldLvl := e.logger.Logger.GetLevel()

	if e.level != oldLvl {
		e.logger.Logger.SetLevel(e.level)
	}

	if len(e.fields) == 0 {
		e.logger.Log(e.level, msg)
	} else {
		e.logger.WithFields(e.fields).Log(e.level, msg)
	}

	if e.level != oldLvl {
		e.logger.Logger.SetLevel(oldLvl)
		e.level = oldLvl
	}
}

func (e *crzLogEvent) Str(key, val string) dbg.Event {
	if e.muted {
		return e
	}
	e.fields[key] = val
	return e
}

func (e *crzLogEvent) Err(err error) dbg.Event {
	if e.muted {
		return e
	}
	e.fields["error"] = err
	return e
}

func (e *crzLogEvent) Bool(key string, b bool) dbg.Event {
	if e.muted {
		return e
	}
	e.fields[key] = b
	return e
}

func (e *crzLogEvent) Int(key string, i int) dbg.Event {
	if e.muted {
		//this allows us to have per-rule debug logging
		if key == "rule_id" && GetRuleDebug(i) {
			e.muted = false
			e.fields = map[string]interface{}{}
			e.level = log.DebugLevel
		} else {
			return e
		}
	}
	e.fields[key] = i
	return e
}

func (e *crzLogEvent) Uint(key string, i uint) dbg.Event {
	if e.muted {
		return e
	}
	e.fields[key] = i
	return e
}

func (e *crzLogEvent) Stringer(key string, val fmt.Stringer) dbg.Event {
	if e.muted {
		return e
	}
	e.fields[key] = val
	return e
}

func (e crzLogEvent) IsEnabled() bool {
	return !e.muted
}

type crzLogger struct {
	logger        *log.Entry
	defaultFields log.Fields
	logLevel      log.Level
}

func NewCrzLogger(logger *log.Entry) crzLogger {
	return crzLogger{logger: logger, logLevel: logger.Logger.GetLevel()}
}

func (c crzLogger) NewMutedEvt(lvl log.Level) dbg.Event {
	return &crzLogEvent{muted: true, logger: c.logger, level: lvl}
}
func (c crzLogger) NewEvt(lvl log.Level) dbg.Event {
	evt := &crzLogEvent{fields: map[string]interface{}{}, logger: c.logger, level: lvl}
	if c.defaultFields != nil {
		for k, v := range c.defaultFields {
			evt.fields[k] = v
		}
	}
	return evt
}

func (c crzLogger) WithOutput(w io.Writer) dbg.Logger {
	return c
}

func (c crzLogger) WithLevel(lvl dbg.Level) dbg.Logger {
	c.logLevel = log.Level(lvl)
	c.logger.Logger.SetLevel(c.logLevel)
	return c
}

func (c crzLogger) With(fs ...dbg.ContextField) dbg.Logger {
	var e dbg.Event = c.NewEvt(c.logLevel)
	for _, f := range fs {
		e = f(e)
	}
	c.defaultFields = e.(*crzLogEvent).fields
	return c
}

func (c crzLogger) Trace() dbg.Event {
	if c.logLevel < log.TraceLevel {
		return c.NewMutedEvt(log.TraceLevel)
	}
	return c.NewEvt(log.TraceLevel)
}

func (c crzLogger) Debug() dbg.Event {
	if c.logLevel < log.DebugLevel {
		return c.NewMutedEvt(log.DebugLevel)

	}
	return c.NewEvt(log.DebugLevel)
}

func (c crzLogger) Info() dbg.Event {
	if c.logLevel < log.InfoLevel {
		return c.NewMutedEvt(log.InfoLevel)
	}
	return c.NewEvt(log.InfoLevel)
}

func (c crzLogger) Warn() dbg.Event {
	if c.logLevel < log.WarnLevel {
		return c.NewMutedEvt(log.WarnLevel)
	}
	return c.NewEvt(log.WarnLevel)
}

func (c crzLogger) Error() dbg.Event {
	if c.logLevel < log.ErrorLevel {
		return c.NewMutedEvt(log.ErrorLevel)
	}
	return c.NewEvt(log.ErrorLevel)
}
