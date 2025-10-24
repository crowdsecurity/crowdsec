package appsec

import (
	"fmt"
	"io"
	"maps"

	dbg "github.com/corazawaf/coraza/v3/debuglog"
	log "github.com/sirupsen/logrus"
)

var DebugRules = map[int]bool{}

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

	if len(e.fields) == 0 {
		e.logger.Log(e.level, msg)
	} else {
		e.logger.WithFields(e.fields).Log(e.level, msg)
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
		if key != "rule_id" || !GetRuleDebug(i) {
			return e
		}
		// this allows us to have per-rule debug logging
		e.muted = false
		e.fields = map[string]any{}
		e.level = log.DebugLevel
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

func (e *crzLogEvent) IsEnabled() bool {
	return !e.muted
}

type crzLogger struct {
	logger        *log.Entry
	defaultFields log.Fields
	logLevel      log.Level
}

func NewCrzLogger(logger *log.Entry) *crzLogger {
	// Create an isolated logger to avoid mutating a shared one at runtime
	base := logger.Logger
	cloned := log.New()
	cloned.SetOutput(base.Out)
	cloned.SetFormatter(base.Formatter)
	cloned.SetReportCaller(base.ReportCaller)
	// Ensure the underlying logger does not drop lower-level records; filtering is handled by crzLogger logic
	cloned.SetLevel(log.TraceLevel)
	// Copy hooks if available (best-effort)
	if base.Hooks != nil {
		cloned.ReplaceHooks(base.Hooks)
	}

	// Preserve existing entry fields as default context
	entry := log.NewEntry(cloned)
	c := &crzLogger{logger: entry, logLevel: logger.Logger.GetLevel()}
	if len(logger.Data) > 0 {
		// store as default fields to be applied to each event
		c.defaultFields = log.Fields{}
		maps.Copy(c.defaultFields, logger.Data)
	}
	return c
}

func (c *crzLogger) NewMutedEvt(lvl log.Level) dbg.Event {
	return &crzLogEvent{muted: true, logger: c.logger, level: lvl}
}

func (c *crzLogger) NewEvt(lvl log.Level) dbg.Event {
	evt := &crzLogEvent{fields: map[string]any{}, logger: c.logger, level: lvl}

	if c.defaultFields != nil {
		maps.Copy(evt.fields, c.defaultFields)
	}

	return evt
}

func (c *crzLogger) WithOutput(w io.Writer) dbg.Logger {
	return c
}

func (c *crzLogger) WithLevel(lvl dbg.Level) dbg.Logger {
	// Adjust only the logical threshold; do not mutate the underlying logger level
	c.logLevel = log.Level(lvl)

	return c
}

func (c *crzLogger) With(fs ...dbg.ContextField) dbg.Logger {
	e := c.NewEvt(c.logLevel)
	for _, f := range fs {
		e = f(e)
	}

	c.defaultFields = e.(*crzLogEvent).fields

	return c
}

func (c *crzLogger) Trace() dbg.Event {
	if c.logLevel < log.TraceLevel {
		return c.NewMutedEvt(log.TraceLevel)
	}

	return c.NewEvt(log.TraceLevel)
}

func (c *crzLogger) Debug() dbg.Event {
	if c.logLevel < log.DebugLevel {
		return c.NewMutedEvt(log.DebugLevel)
	}

	return c.NewEvt(log.DebugLevel)
}

func (c *crzLogger) Info() dbg.Event {
	if c.logLevel < log.InfoLevel {
		return c.NewMutedEvt(log.InfoLevel)
	}

	return c.NewEvt(log.InfoLevel)
}

func (c *crzLogger) Warn() dbg.Event {
	if c.logLevel < log.WarnLevel {
		return c.NewMutedEvt(log.WarnLevel)
	}

	return c.NewEvt(log.WarnLevel)
}

func (c *crzLogger) Error() dbg.Event {
	if c.logLevel < log.ErrorLevel {
		return c.NewMutedEvt(log.ErrorLevel)
	}

	return c.NewEvt(log.ErrorLevel)
}
