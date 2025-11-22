package logging

import (
	"github.com/sirupsen/logrus"
)

// SubLogger creates a logrus.Entry object that inherits the formatter,
// output, and hooks from the given base logger, but can have a different
// log level and optional module field.
//
// If module == "", no field is added.
// If level == 0 (panic), the log level is inherited too.
func SubLogger(base *logrus.Logger, module string, level logrus.Level) *logrus.Entry {
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

	var fields logrus.Fields

	if module != "" {
		fields = logrus.Fields{
			"module": module,
		}
	}

	return l.WithFields(fields)
}
