package tailwrapper

import (
	"time"
)

// Tailer is the interface that all tail implementations must satisfy
type Tailer interface {
	Filename() string
	Lines() <-chan *Line
	Dying() <-chan struct{}
	Err() error
	Stop() error
}

// Line represents a line read from a file
type Line struct {
	Text string
	Time time.Time
	Err  error
}

// SeekInfo represents where to start reading from a file
type SeekInfo struct {
	Offset int64
	Whence int // io.SeekStart, io.SeekEnd, etc.
}

// Config holds configuration for tailing a file
type Config struct {
	ReOpen           bool
	Follow           bool
	Poll             bool
	Location         *SeekInfo
	Logger           interface{}   // *log.Entry, but we use interface{} to avoid circular deps
	TailMode         string        // "default" or "stat" (defaults to "default" if empty)
	StatPollInterval time.Duration // for stat mode: default 1s, 0 = 1s, -1 = no automatic polling (manual/test mode)
}
