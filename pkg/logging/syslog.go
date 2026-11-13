//go:build !windows

package logging

import (
	"io"
	"log/syslog"

	"github.com/sirupsen/logrus"
)

func setupSyslogDefault() error {
	// already set up by a previous config load (SIGHUP)
	if HasHook[*FormatterSyslogHook](logrus.StandardLogger()) {
		logrus.SetOutput(io.Discard)
		return nil
	}

	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "crowdsec")
	if err != nil {
		return err
	}

	hook := NewFormatterSyslogHook(w)
	logrus.AddHook(hook)
	logrus.SetOutput(io.Discard)

	return nil
}

// removeSyslogHooks drops the hooks left by a previous config load that used log_media: syslog.
func removeSyslogHooks(logger *logrus.Logger) {
	hooks := make(logrus.LevelHooks)
	writers := make(map[*syslog.Writer]struct{})

	for lvl, hs := range logger.Hooks {
		for _, h := range hs {
			if sh, ok := h.(*FormatterSyslogHook); ok {
				writers[sh.Writer] = struct{}{}
				continue
			}

			hooks[lvl] = append(hooks[lvl], h)
		}
	}

	logger.ReplaceHooks(hooks)

	for w := range writers {
		if w != nil {
			_ = w.Close()
		}
	}
}

type SyslogFormatter struct{}

func (*SyslogFormatter) Format(e *logrus.Entry) ([]byte, error) {
	return []byte(e.Message + "\n"), nil
}

type FormatterSyslogHook struct {
	Writer    *syslog.Writer
	Formatter logrus.Formatter
}

func NewFormatterSyslogHook(w *syslog.Writer) *FormatterSyslogHook {
	return &FormatterSyslogHook{Writer: w, Formatter: &SyslogFormatter{}}
}

func (h *FormatterSyslogHook) Fire(entry *logrus.Entry) error {
	msg, err := h.Formatter.Format(entry)
	if err != nil {
		return err
	}

	switch entry.Level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return h.Writer.Crit(string(msg))
	case logrus.ErrorLevel:
		return h.Writer.Err(string(msg))
	case logrus.WarnLevel:
		return h.Writer.Warning(string(msg))
	case logrus.InfoLevel:
		return h.Writer.Info(string(msg))
	case logrus.DebugLevel, logrus.TraceLevel:
		return h.Writer.Debug(string(msg))
	}
	return nil
}

func (*FormatterSyslogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
