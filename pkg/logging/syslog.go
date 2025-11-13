package logging

import (
	"log/syslog"

	"github.com/sirupsen/logrus"
)

type SyslogFormatter struct{}

func (f *SyslogFormatter) Format(e *logrus.Entry) ([]byte, error) {
//	level := strings.ToUpper(e.Level.String())
//	msg := fmt.Sprintf("[%s] %s\n", level, e.Message)
//	return []byte(msg), nil
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
    // choose syslog method based on level
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
