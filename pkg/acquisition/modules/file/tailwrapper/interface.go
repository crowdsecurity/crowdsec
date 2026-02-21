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
	// File behavior
	ReOpen   bool      // Reopen file if it's rotated/truncated (always recommended for log files)
	Location *SeekInfo // Where to start reading from

	// Change detection
	Poll         bool          // Use polling instead of inotify for change detection
	PollInterval time.Duration // Polling interval (default 1s, 0 = 1s, -1 = manual/test mode)

	// File handle mode
	// When true: keeps file handle open between reads (better performance, uses inotify/polling for changes)
	// When false: opens file, reads new content, closes immediately (works better on network shares like Azure SMB)
	KeepFileOpen bool
}
