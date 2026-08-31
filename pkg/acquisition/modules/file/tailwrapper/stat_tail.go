package tailwrapper

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/tomb.v2"
)

// statTail implements Tailer using stat-based polling that doesn't keep file handles open
type statTail struct {
	filename   string
	config     Config
	lines      chan *Line
	dying      chan struct{}
	tomb       *tomb.Tomb
	mu         sync.Mutex
	lastOffset int64
	lastSize   int64
	stopped    bool
}

// newStatTail creates a new stat-based tailer
func newStatTail(filename string, config Config) (Tailer, error) {
	// Initialize file state
	fi, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("could not stat file %s: %w", filename, err)
	}

	// Determine initial offset
	initialOffset := int64(0)
	if config.Location != nil {
		initialOffset = config.Location.Offset
		if config.Location.Whence == io.SeekEnd {
			initialOffset = fi.Size()
		}
	}

	st := &statTail{
		filename:   filename,
		config:     config,
		lines:      make(chan *Line, 100), // buffered channel
		dying:      make(chan struct{}),
		tomb:       &tomb.Tomb{},
		lastOffset: initialOffset,
		lastSize:   0, // Start with 0 so first ForceRead() will process the file
	}

	// Start polling goroutine
	st.tomb.Go(st.pollLoop)

	return st, nil
}

// Filename returns the filename being tailed
func (s *statTail) Filename() string {
	return s.filename
}

// Lines returns a channel of lines read from the file
func (s *statTail) Lines() <-chan *Line {
	return s.lines
}

// Dying returns a channel that will be closed when the tailer is dying
func (s *statTail) Dying() <-chan struct{} {
	return s.dying
}

// Err returns any error that occurred during tailing
func (s *statTail) Err() error {
	return s.tomb.Err()
}

// Stop stops the tailer
func (s *statTail) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.mu.Unlock()

	// Don't overwrite any existing error in tomb
	s.tomb.Kill(nil)
	err := s.tomb.Wait()
	close(s.dying)
	close(s.lines)
	return err
}

// pollLoop is the main polling loop that checks for file changes
func (s *statTail) pollLoop() error {
	pollInterval := s.config.StatPollInterval
	if pollInterval == 0 {
		pollInterval = 1 * time.Second // default
	}

	// Note: We don't do an automatic initial read here
	// The initial read happens when the user first calls ForceRead() in manual mode,
	// or on the first ticker interval in automatic mode

	// If pollInterval is -1, don't poll automatically (manual mode for testing)
	if pollInterval < 0 {
		// Just wait for tomb to die, no automatic polling
		<-s.tomb.Dying()
		return nil
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.tomb.Dying():
			return nil
		case <-ticker.C:
			s.readNewLines()
		}
	}
}

// ForceRead is a test-only method that forces a read cycle (as if the poll timer triggered)
// This is useful for testing without waiting for the poll interval
func (s *statTail) ForceRead() {
	s.readNewLines()
}

// readNewLines opens the file, reads new lines, and closes it immediately
func (s *statTail) readNewLines() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return
	}

	// Stat the file to check for changes
	fi, err := os.Stat(s.filename)
	if err != nil {
		// File might be deleted or inaccessible
		if os.IsNotExist(err) {
			// File deleted, mark as dying so CrowdSec can recover
			s.tomb.Kill(fmt.Errorf("file %s no longer exists", s.filename))
			return
		}
		// Other error - propagate so CrowdSec can recover
		s.tomb.Kill(fmt.Errorf("error statting file %s: %w", s.filename, err))
		return
	}

	// Detect truncation: file size decreased compared to last known size
	// Use lastSize instead of lastOffset because Azure metadata cache can cause
	// size and offset to differ slightly, making offset-based detection unreliable
	truncated := fi.Size() < s.lastSize

	if truncated {
		// Reset position to start (both SeekEnd and SeekStart read from beginning after truncation)
		s.lastOffset = 0
		// Don't update lastSize yet - we'll update it after reading
		// This ensures we read the truncated content
	}

	// Check if file has new content
	// Compare against lastSize to account for Azure metadata cache differences
	// If truncated, we always want to read (to get the truncated content)
	if fi.Size() <= s.lastSize && !truncated {
		// No new content
		s.lastSize = fi.Size() // Update lastSize even when no new content
		return
	}

	// Open file and read new lines
	fd, err := os.Open(s.filename)
	if err != nil {
		// File might be locked or permission denied - propagate error
		s.tomb.Kill(fmt.Errorf("error opening file %s: %w", s.filename, err))
		return
	}
	defer fd.Close()

	// Seek to last known position
	_, err = fd.Seek(s.lastOffset, io.SeekStart)
	if err != nil {
		// Seek error - propagate so CrowdSec can recover
		s.tomb.Kill(fmt.Errorf("error seeking in file %s: %w", s.filename, err))
		return
	}

	// Read new lines using bufio.Reader.ReadString()
	// This matches the behavior of the nxadm/tail library and can handle lines of any size
	// Unlike bufio.Scanner which has a 64KB limit, ReadString() dynamically grows the buffer
	reader := bufio.NewReader(fd)

	bytesRead := int64(0)

	for {
		line, err := reader.ReadString('\n')

		// ReadString returns the data read before the error, so we process the line first
		if line != "" {
			// Trim the newline for consistency with Scanner behavior
			lineText := strings.TrimRight(line, "\n\r")

			// Calculate bytes read (including newline characters)
			lineBytes := len(line)
			bytesRead += int64(lineBytes)

			// Send line to channel (non-blocking)
			select {
			case s.lines <- &Line{
				Text: lineText,
				Time: time.Now(),
				Err:  nil,
			}:
			case <-s.tomb.Dying():
				return
			}
		}

		// Handle errors
		if err != nil {
			if err == io.EOF {
				// Reached end of file, this is expected
				break
			}
			// Other error - propagate upstream
			s.tomb.Kill(fmt.Errorf("error reading file %s: %w", s.filename, err))
			return
		}
	}

	// Update position: lastOffset + bytes we just read
	// This accounts for all complete lines we processed
	s.lastOffset += bytesRead

	// If we're at EOF and the file size matches, we're caught up
	// Otherwise, we might have an incomplete line that will be read next time
	if s.lastOffset > fi.Size() {
		// Shouldn't happen, but use file size as fallback
		s.lastOffset = fi.Size()
	}

	// Always update lastSize from stat() result to track file size accurately
	// This is important for Azure metadata cache where size and offset may differ
	s.lastSize = fi.Size()
}
