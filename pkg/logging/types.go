package logging

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type LogConfig interface {
	GetFormat()                        string
	GetMedia()                         string
	NewRotatingLogger(filename string) *lumberjack.Logger
}

// ExtLogger is a common interface for logrus.Logger and logrus.Entry.
// Much like Ext1FieldLogger from logrus.go, it says not to use it, yet it's currently the best option.
type ExtLogger interface {
	logrus.FieldLogger
	Tracef(format string, args ...any)
	Trace(args ...any)
	Traceln(args ...any)
}
