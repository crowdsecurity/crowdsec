package logging

import (
	"github.com/sirupsen/logrus"
)

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
