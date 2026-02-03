package tailwrapper

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	defaultPollInterval = 1 * time.Second
)

// tailer is a unified file tailer that supports two modes:
// - KeepFileOpen=true: keeps file handle open, uses fsnotify for change detection (like traditional tail -f)
// - KeepFileOpen=false: opens/reads/closes on each poll cycle (works on network shares like Azure SMB)
type tailer struct {
	filename string
	config   Config
	lines    chan *Line
	dying    chan struct{}

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Synchronization
	mu      sync.Mutex
	wg      sync.WaitGroup
	stopped bool
	err     error

	// For KeepFileOpen=true mode
	file    *os.File
	reader  *bufio.Reader
	watcher *fsnotify.Watcher

	// Position tracking (used by both modes)
	lastOffset int64
	lastSize   int64
}

// TailFile creates a new Tailer with the specified configuration.
//
// The behavior depends on config.KeepFileOpen:
//   - true:  keeps file handle open, uses fsnotify for change detection (better for local files)
//   - false: opens/reads/closes on each poll cycle (better for network shares like Azure SMB)
func TailFile(ctx context.Context, filename string, config Config) (Tailer, error) {
	// Validate file exists
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

	// Create a child context so we can cancel independently
	childCtx, cancel := context.WithCancel(ctx)

	t := &tailer{
		filename:   filename,
		config:     config,
		lines:      make(chan *Line, 100),
		dying:      make(chan struct{}),
		ctx:        childCtx,
		cancel:     cancel,
		lastOffset: initialOffset,
		lastSize:   fi.Size(),
	}

	// Initialize based on mode
	if config.KeepFileOpen {
		if err := t.initKeepOpenMode(); err != nil {
			cancel()
			return nil, err
		}
	}

	// Start the main loop
	t.wg.Add(1)
	go t.mainLoop()

	return t, nil
}

// initKeepOpenMode initializes resources for KeepFileOpen=true mode
func (t *tailer) initKeepOpenMode() error {
	// Open the file
	file, err := openFile(t.filename)
	if err != nil {
		return fmt.Errorf("could not open file %s: %w", t.filename, err)
	}
	t.file = file

	// Seek to initial position
	if _, err := t.file.Seek(t.lastOffset, io.SeekStart); err != nil {
		t.file.Close()
		return fmt.Errorf("could not seek in file %s: %w", t.filename, err)
	}

	// Create buffered reader
	t.reader = bufio.NewReader(t.file)

	// Set up fsnotify watcher if not using polling
	if !t.config.Poll {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			t.file.Close()
			return fmt.Errorf("could not create fsnotify watcher: %w", err)
		}
		if err := watcher.Add(t.filename); err != nil {
			watcher.Close()
			t.file.Close()
			return fmt.Errorf("could not watch file %s: %w", t.filename, err)
		}
		t.watcher = watcher
	}

	return nil
}

// Filename returns the filename being tailed
func (t *tailer) Filename() string {
	return t.filename
}

// Lines returns a channel of lines read from the file
func (t *tailer) Lines() <-chan *Line {
	return t.lines
}

// Dying returns a channel that will be closed when the tailer is dying
func (t *tailer) Dying() <-chan struct{} {
	return t.dying
}

// Err returns any error that occurred during tailing
func (t *tailer) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

// Stop stops the tailer
func (t *tailer) Stop() error {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return nil
	}
	t.stopped = true
	t.mu.Unlock()

	// Cancel context to stop goroutine
	t.cancel()

	// Wait for goroutine to finish
	t.wg.Wait()

	// Close channels
	close(t.dying)
	close(t.lines)

	// Cleanup resources
	t.cleanup()

	return t.Err()
}

// cleanup releases resources
func (t *tailer) cleanup() {
	if t.watcher != nil {
		t.watcher.Close()
		t.watcher = nil
	}
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
}

// setError stores an error and triggers shutdown
func (t *tailer) setError(err error) {
	t.mu.Lock()
	if t.err == nil {
		t.err = err
	}
	t.mu.Unlock()
	t.cancel()
}

// mainLoop is the main polling/watching loop
func (t *tailer) mainLoop() {
	defer t.wg.Done()

	pollInterval := t.config.PollInterval
	if pollInterval == 0 {
		pollInterval = defaultPollInterval
	}

	// Manual mode for testing (-1 interval)
	if pollInterval < 0 {
		<-t.ctx.Done()
		return
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// For KeepFileOpen mode with fsnotify
	var fsEvents <-chan fsnotify.Event
	var fsErrors <-chan error
	if t.watcher != nil {
		fsEvents = t.watcher.Events
		fsErrors = t.watcher.Errors
	}

	for {
		select {
		case <-t.ctx.Done():
			return

		case <-ticker.C:
			t.checkAndRead()

		case event, ok := <-fsEvents:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				t.checkAndRead()
			}
			if event.Op&fsnotify.Remove != 0 {
				// File was removed
				if t.config.ReOpen {
					t.handleFileRemoved()
				} else {
					t.setError(fmt.Errorf("file %s was removed", t.filename))
					return
				}
			}

		case err, ok := <-fsErrors:
			if !ok {
				return
			}
			t.setError(fmt.Errorf("fsnotify error: %w", err))
			return
		}
	}
}

// checkAndRead checks for new content and reads it
func (t *tailer) checkAndRead() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return
	}

	if t.config.KeepFileOpen {
		t.readKeepOpenMode()
	} else {
		t.readStatMode()
	}
}

// readKeepOpenMode reads new content with file handle kept open
func (t *tailer) readKeepOpenMode() {
	// Check for truncation
	fi, err := t.file.Stat()
	if err != nil {
		t.setErrorLocked(fmt.Errorf("error statting file %s: %w", t.filename, err))
		return
	}

	currentSize := fi.Size()
	if currentSize < t.lastSize {
		// File was truncated, reopen from beginning
		t.reopenFile(0)
		t.lastSize = 0
	}

	// Read available lines
	t.readLines()

	// Update last known size
	t.lastSize = currentSize
}

// readStatMode reads new content using open/read/close pattern
func (t *tailer) readStatMode() {
	// Stat the file to check for changes
	fi, err := os.Stat(t.filename)
	if err != nil {
		if os.IsNotExist(err) {
			t.setErrorLocked(fmt.Errorf("file %s no longer exists", t.filename))
			return
		}
		t.setErrorLocked(fmt.Errorf("error statting file %s: %w", t.filename, err))
		return
	}

	// Detect truncation
	truncated := fi.Size() < t.lastSize
	if truncated {
		t.lastOffset = 0
	}

	// Check if file has new content to read
	// Either: file grew since last read, or we haven't read up to current position yet, or file was truncated
	if fi.Size() <= t.lastOffset && !truncated {
		t.lastSize = fi.Size()
		return
	}

	// Open file and read new lines
	fd, err := openFile(t.filename)
	if err != nil {
		t.setErrorLocked(fmt.Errorf("error opening file %s: %w", t.filename, err))
		return
	}
	defer fd.Close()

	// Seek to last known position
	if _, err := fd.Seek(t.lastOffset, io.SeekStart); err != nil {
		t.setErrorLocked(fmt.Errorf("error seeking in file %s: %w", t.filename, err))
		return
	}

	// Read new lines
	reader := bufio.NewReader(fd)
	bytesRead := int64(0)

	for {
		line, err := reader.ReadString('\n')

		if line != "" {
			lineText := strings.TrimRight(line, "\n\r")
			bytesRead += int64(len(line))

			select {
			case t.lines <- &Line{
				Text: lineText,
				Time: time.Now(),
				Err:  nil,
			}:
			case <-t.ctx.Done():
				return
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			t.setErrorLocked(fmt.Errorf("error reading file %s: %w", t.filename, err))
			return
		}
	}

	t.lastOffset += bytesRead
	if t.lastOffset > fi.Size() {
		t.lastOffset = fi.Size()
	}
	t.lastSize = fi.Size()
}

// readLines reads all available lines from the current reader (KeepFileOpen mode)
func (t *tailer) readLines() {
	for {
		line, err := t.reader.ReadString('\n')

		if line != "" {
			lineText := strings.TrimRight(line, "\n\r")

			select {
			case t.lines <- &Line{
				Text: lineText,
				Time: time.Now(),
				Err:  nil,
			}:
			case <-t.ctx.Done():
				return
			}
		}

		if err != nil {
			if err == io.EOF {
				// Update our position
				pos, _ := t.file.Seek(0, io.SeekCurrent)
				t.lastOffset = pos - int64(t.reader.Buffered())
				return
			}
			t.setErrorLocked(fmt.Errorf("error reading file %s: %w", t.filename, err))
			return
		}
	}
}

// reopenFile reopens the file at the specified offset (KeepFileOpen mode)
func (t *tailer) reopenFile(offset int64) {
	if t.file != nil {
		t.file.Close()
	}

	file, err := openFile(t.filename)
	if err != nil {
		t.setErrorLocked(fmt.Errorf("error reopening file %s: %w", t.filename, err))
		return
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		file.Close()
		t.setErrorLocked(fmt.Errorf("error seeking in file %s: %w", t.filename, err))
		return
	}

	t.file = file
	t.reader = bufio.NewReader(file)
	t.lastOffset = offset
}

// handleFileRemoved handles file removal in KeepFileOpen mode
func (t *tailer) handleFileRemoved() {
	// Close current file handle (with lock)
	t.mu.Lock()
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
	t.mu.Unlock()

	// Wait for file to reappear (without holding lock)
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			fi, err := os.Stat(t.filename)
			if err == nil {
				// File exists again, reopen (with lock)
				t.mu.Lock()
				t.reopenFile(0)
				t.lastSize = fi.Size()

				// Re-add to watcher
				if t.watcher != nil {
					_ = t.watcher.Add(t.filename)
				}
				t.mu.Unlock()
				return
			}
		}
	}
}

// setErrorLocked stores an error (caller must hold t.mu)
func (t *tailer) setErrorLocked(err error) {
	if t.err == nil {
		t.err = err
	}
	// Release lock before cancel to avoid potential deadlock
	t.mu.Unlock()
	t.cancel()
	t.mu.Lock()
}

// ForceRead is a test-only method that forces a read cycle
func (t *tailer) ForceRead() {
	t.checkAndRead()
}

// openFile opens a file for reading, handling OS-specific requirements
func openFile(filename string) (*os.File, error) {
	if runtime.GOOS == "windows" {
		// On Windows, open with shared read access to allow other processes to write
		return os.OpenFile(filename, os.O_RDONLY, 0)
	}
	return os.Open(filename)
}
