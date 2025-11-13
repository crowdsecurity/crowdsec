package logging

import (
	"github.com/sirupsen/logrus"
)

// CloneLogger creates a new *logrus.Logger that inherits the formatter,
// output, and hooks from the given base logger, but can have a different log level.
//
// If level == 0 (panic), the log level is inherited too.
func CloneLogger(base *logrus.Logger, level logrus.Level) *logrus.Logger {
	l := logrus.New()
	l.SetFormatter(base.Formatter)
	l.SetOutput(base.Out)

	for _, hooks := range base.Hooks {
		for _, h := range hooks {
			l.AddHook(h)
		}
	}

	if level == 0 {
		level = base.GetLevel()
	}

	l.SetLevel(level)

	return l
}
