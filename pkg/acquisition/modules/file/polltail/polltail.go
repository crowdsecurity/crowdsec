// Package polltail tails a file without keeping a handle open. Each pass opens the path, reads new lines, and closes it.
// It does not overlap or try to replace what nxadm does.
// If the file is rotated with mv, lines can be lost. This tailer does not stay with the original file,
// so anything written there after the last check is never read. The purpose of this tailer is to support
// deployments where keeping an open handle permanently has drawbacks (i.e. not being able to rotate the files).
package polltail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultPollInterval = 1 * time.Second
)

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

// Config selects where to start and how often the path is read.
// Each pass stats the path, opens it, reads, and closes it.
type Config struct {
	Location     *SeekInfo     // Where to start reading from
	PollInterval time.Duration // How often to read (default 1s, 0 = 1s, negative = manual/test mode)
}

// PollTail follows one file and sends each newline-terminated line.
// Each pass opens the path, reads new lines, and closes it.
type PollTail struct {
	filename string
	config   Config
	lines    chan *Line
	dying    chan struct{}

	// done closes when Stop or the first recorded error cancels the loop.
	done   <-chan struct{}
	cancel context.CancelFunc

	mu      sync.Mutex
	wg      sync.WaitGroup
	stopped bool
	err     error
	// followEnded closes Dying and Lines once, when Stop returns or the follow loop itself ends.
	followEnded sync.Once

	// lastOffset is the next byte to read. lastSize is the previous stat size, and only that size decides a shrink.
	// lastPathInfo is the file at filename on the previous pass. A different file means the path was replaced.
	lastOffset   int64
	lastSize     int64
	lastPathInfo os.FileInfo
}

// TailFile starts following filename. A missing file is an error. SeekEnd starts at the current end of the file.
func TailFile(ctx context.Context, filename string, config Config) (*PollTail, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("could not stat file %s: %w", filename, err)
	}

	// Start tailing from the configured position. SeekEnd is the current end of the file.
	initialOffset := startingOffset(fileInfo.Size(), config.Location)

	tailerCtx, cancel := context.WithCancel(ctx)
	fileTailer := &PollTail{
		filename:     filename,
		config:       config,
		lines:        make(chan *Line, 100),
		dying:        make(chan struct{}),
		done:         tailerCtx.Done(),
		cancel:       cancel,
		lastOffset:   initialOffset,
		lastSize:     fileInfo.Size(),
		lastPathInfo: fileInfo,
	}

	fileTailer.wg.Add(1)
	go fileTailer.pollUntilStopped()

	return fileTailer, nil
}

// startingOffset is the first byte to read.
// SeekEnd starts at the current end, as nxadm does. A fragment already in the file is LEFT BEHIND.
// Every other whence uses Offset as that byte.
func startingOffset(size int64, location *SeekInfo) int64 {
	if location == nil {
		return 0
	}
	if location.Whence == io.SeekEnd {
		return size
	}
	return location.Offset
}

// Filename is the path this tailer was started on.
func (fileTailer *PollTail) Filename() string {
	return fileTailer.filename
}

// Lines delivers each newline-terminated line. Stop closes the channel.
func (fileTailer *PollTail) Lines() <-chan *Line {
	return fileTailer.lines
}

// Dying closes when the follow has ended.
func (fileTailer *PollTail) Dying() <-chan struct{} {
	return fileTailer.dying
}

// Err is the first failure that stopped this tailer, or nil.
func (fileTailer *PollTail) Err() error {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()
	return fileTailer.err
}

// Stop cancels the follow loop, then closes Lines and Dying.
func (fileTailer *PollTail) Stop() error {
	fileTailer.mu.Lock()
	if fileTailer.stopped {
		fileTailer.mu.Unlock()
		return nil
	}
	fileTailer.stopped = true
	fileTailer.mu.Unlock()

	fileTailer.cancel()
	fileTailer.wg.Wait()
	fileTailer.closeDyingAndReleaseHandle()

	return fileTailer.Err()
}

// closeDyingAndReleaseHandle closes Dying and Lines once so the reader can drop the tail.
func (fileTailer *PollTail) closeDyingAndReleaseHandle() {
	fileTailer.followEnded.Do(func() {
		close(fileTailer.dying)
		close(fileTailer.lines)
	})
}

// recordFirstErrorAndStop keeps the first error and cancels the follow loop.
func (fileTailer *PollTail) recordFirstErrorAndStop(err error) {
	fileTailer.mu.Lock()
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.mu.Unlock()
	fileTailer.cancel()
}

// pollUntilStopped reads on each poll tick until Stop or the first recorded error.
func (fileTailer *PollTail) pollUntilStopped() {
	defer fileTailer.wg.Done()
	defer fileTailer.closeDyingAndReleaseHandle()

	pollInterval := fileTailer.config.PollInterval
	if pollInterval == 0 {
		pollInterval = defaultPollInterval
	}

	// A negative interval is the manual test mode: read only when a test asks.
	if pollInterval < 0 {
		<-fileTailer.done
		return
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fileTailer.done:
			return
		case <-ticker.C:
			fileTailer.readLines()
		}
	}
}

// readLines stats the path, then opens it to read lines past lastOffset.
// The offset is not moved back to the size from before the read, so a line appended during the read is not sent twice.
func (fileTailer *PollTail) readLines() {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()

	if fileTailer.stopped {
		return
	}

	fileInfo, err := statFile(fileTailer.filename)
	if filePathGone(err) {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("file %s no longer exists", fileTailer.filename))
		return
	}
	if err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error statting file %s: %w", fileTailer.filename, err))
		return
	}

	// A shrink of this file, or a different file at this path, is read from the first byte.
	replaced := fileTailer.lastPathInfo != nil && !os.SameFile(fileTailer.lastPathInfo, fileInfo)
	rotated := fileInfo.Size() < fileTailer.lastSize
	fileTailer.lastPathInfo = fileInfo
	if rotated || replaced {
		fileTailer.lastOffset = 0
	}

	if !fileNeedsAnotherRead(fileInfo.Size(), fileTailer.lastOffset, rotated) {
		fileTailer.lastSize = fileInfo.Size()
		return
	}

	openedFile, err := openFileForRead(fileTailer.filename)
	if err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error opening file %s: %w", fileTailer.filename, err))
		return
	}
	defer func() {
		closeErr := openedFile.Close()
		if closeErr == nil || fileTailer.err != nil {
			return
		}
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error closing file %s: %w", fileTailer.filename, closeErr))
	}()

	if _, err := openedFile.Seek(fileTailer.lastOffset, io.SeekStart); err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error seeking in file %s: %w", fileTailer.filename, err))
		return
	}

	reader := bufio.NewReader(openedFile)
	completeBytes, _, readErr := fileTailer.sendCompleteLines(reader)
	if readErr != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error reading file %s: %w", fileTailer.filename, readErr))
		return
	}

	fileTailer.lastOffset += completeBytes
	// A filesystem with a metadata cache can make Stat smaller than the bytes just read. Keep that size a stat, or the next poll looks like a shrink.
	fileInfoAfterRead, statErr := statOpenedFile(openedFile)
	if statErr != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error statting file %s: %w", fileTailer.filename, statErr))
		return
	}
	fileTailer.lastSize = fileInfoAfterRead.Size()
}

// fileNeedsAnotherRead is true when the file was rotated or grew past the last byte already sent.
func fileNeedsAnotherRead(size int64, lastOffset int64, rotated bool) bool {
	if rotated {
		return true
	}
	return size > lastOffset
}

// sendCompleteLines sends chunks that end with a newline.
// completeBytes counts those chunks. pendingBytes is a trailing fragment at EOF and is not sent.
func (fileTailer *PollTail) sendCompleteLines(reader *bufio.Reader) (int64, int64, error) {
	var completeBytes int64
	for {
		// A file with no line breaks is read until EOF. ReadString grows until '\n', so one pass can hold the whole file. That is assumed, and matches nxadm.
		chunk, readErr := reader.ReadString('\n')
		endedWithNewline := strings.HasSuffix(chunk, "\n")

		// A chunk with no newline is not a line. A real read error drops it; EOF holds it.
		if chunk != "" && !endedWithNewline {
			if readErr != nil && readErr != io.EOF {
				return completeBytes, 0, readErr
			}
			return completeBytes, int64(len(chunk)), nil
		}

		if endedWithNewline {
			completeBytes += int64(len(chunk))
			lineText := strings.TrimRight(chunk, "\n\r")
			if fileTailer.enqueueLine(lineText) {
				return completeBytes, 0, nil
			}
		}

		if readErr == nil {
			continue
		}
		if readErr == io.EOF {
			return completeBytes, 0, nil
		}
		return completeBytes, 0, readErr
	}
}

// enqueueLine sends one complete line. followStopped is true when the follow loop was canceled before the send.
func (fileTailer *PollTail) enqueueLine(lineText string) (followStopped bool) {
	select {
	case fileTailer.lines <- &Line{
		Text: lineText,
		Time: time.Now(),
	}:
		return false
	case <-fileTailer.done:
		return true
	}
}

// recordFirstErrorAndStopWhileLocked keeps the first error and cancels the follow loop.
// The caller holds mu. cancel does not take it, so the lock stays with the caller.
func (fileTailer *PollTail) recordFirstErrorAndStopWhileLocked(err error) {
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.cancel()
}

// Extension points for tests that pin behavior.
//
// Production leaves each variable nil. The function under it then calls the real OS operation.
// A test sets the variable to force a result the OS will not produce on demand: a transient stat
// error, a stat error on the handle just read, or an open that is not the log file. The test
// restores the previous value when it finishes, so later tests see the real OS calls again.
var (
	openFileForReadInTest func(filename string) (*os.File, error)
	statFileInTest        func(name string) (os.FileInfo, error)
	statOpenedFileInTest  func(file *os.File) (os.FileInfo, error)
)

// openFileForRead opens filename for a shared read so another process can still append, rename, or delete it.
func openFileForRead(filename string) (*os.File, error) {
	if openFileForReadInTest == nil {
		return openSharedRead(filename)
	}
	return openFileForReadInTest(filename)
}

// statFile stats the path before the read.
func statFile(name string) (os.FileInfo, error) {
	if statFileInTest == nil {
		return os.Stat(name)
	}
	return statFileInTest(name)
}

// statOpenedFile stats the handle that was just read.
func statOpenedFile(file *os.File) (os.FileInfo, error) {
	if statOpenedFileInTest == nil {
		return file.Stat()
	}
	return statOpenedFileInTest(file)
}
