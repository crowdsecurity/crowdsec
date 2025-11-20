package tailwrapper

import (
	"github.com/nxadm/tail"
)

// nxadmTailAdapter wraps the original tail.Tail to implement our Tailer interface
type nxadmTailAdapter struct {
	tail *tail.Tail
}

// Filename returns the filename being tailed
func (a *nxadmTailAdapter) Filename() string {
	return a.tail.Filename
}

// Lines returns a channel of lines read from the file
func (a *nxadmTailAdapter) Lines() <-chan *Line {
	// Convert tail.Line to our Line type
	ch := make(chan *Line)
	go func() {
		defer close(ch)
		for line := range a.tail.Lines {
			if line == nil {
				continue
			}
			ch <- &Line{
				Text: line.Text,
				Time: line.Time,
				Err:  line.Err,
			}
		}
	}()
	return ch
}

// Dying returns a channel that will be closed when the tailer is dying
func (a *nxadmTailAdapter) Dying() <-chan struct{} {
	return a.tail.Dying()
}

// Err returns any error that occurred during tailing
func (a *nxadmTailAdapter) Err() error {
	return a.tail.Err()
}

// Stop stops the tailer
func (a *nxadmTailAdapter) Stop() error {
	return a.tail.Stop()
}

// newNxadmTail creates a new nxadm tail adapter from the original tail library
func newNxadmTail(filename string, config Config) (Tailer, error) {
	// Convert our Config to tail.Config
	seekInfo := &tail.SeekInfo{
		Offset: config.Location.Offset,
		Whence: config.Location.Whence,
	}

	tailConfig := tail.Config{
		ReOpen:   config.ReOpen,
		Follow:   config.Follow,
		Poll:     config.Poll,
		Location: seekInfo,
		// Logger is not set - tail library will use its default logger
		// The original tail library's logger interface is different from logrus.Entry
	}

	t, err := tail.TailFile(filename, tailConfig)
	if err != nil {
		return nil, err
	}

	return &nxadmTailAdapter{tail: t}, nil
}
