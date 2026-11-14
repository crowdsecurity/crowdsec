package logging

import (
	"slices"

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

	// Copy per level: AddHook() would register each hook again for all of its levels.
	for lvl, hooks := range base.Hooks {
		l.Hooks[lvl] = slices.Clone(hooks)
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

// HasHook reports whether a hook of type T is registered on the logger.
func HasHook[T logrus.Hook](logger *logrus.Logger) bool {
	for _, hooks := range logger.Hooks {
		for _, h := range hooks {
			if _, ok := h.(T); ok {
				return true
			}
		}
	}

	return false
}
