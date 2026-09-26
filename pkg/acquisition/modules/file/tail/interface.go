package tail

import (
	"time"
)

// Tailer is one file being followed for newline-terminated lines.
type Tailer interface {
	// Filename is the path this tailer was started on.
	Filename() string
	// Lines delivers each newline-terminated line. The channel closes when the follow ends.
	Lines() <-chan *Line
	// Dying closes when the follow has ended, including a missing file or a failed reopen.
	Dying() <-chan struct{}
	// Err is the first failure that stopped the tailer, or nil.
	Err() error
	// Stop cancels the follow loop and closes Lines and Dying. It is safe after the follow has already ended.
	Stop() error
}

// Line is one newline-terminated read, or the error that ended the read.
type Line struct {
	Text string
	Time time.Time
	Err  error
}

// SeekInfo is the file position where following starts.
type SeekInfo struct {
	Offset int64
	Whence int // io.SeekStart, io.SeekEnd, etc.
}

// Config selects where to start, how changes are noticed, and whether the handle stays open.
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
