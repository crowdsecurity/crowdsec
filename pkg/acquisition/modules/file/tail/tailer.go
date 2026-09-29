// Package tail checks a log file every so often and reads the new lines.
// It does not keep the file open between checks. It does not overlap or try
// to replace what admx does so to keep it as focused as possible.
// If the file is rotated with mv, lines can be lost. This tailer does not stay with the original file,
// so anything written there after the last check is never read.
package tail

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

// Tailer follows one file and sends each newline-terminated line.
// Each pass opens the path, reads new lines, and closes it.
type Tailer struct {
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

	// lastOffset is the next byte to read. lastSize is the size after the previous pass.
	// lastPathInfo is the file at filename on the previous pass. A different file means the path was replaced.
	lastOffset   int64
	lastSize     int64
	lastPathInfo os.FileInfo
}

// TailFile starts following filename. A missing file is an error. SeekEnd starts after the last newline.
func TailFile(ctx context.Context, filename string, config Config) (*Tailer, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("could not stat file %s: %w", filename, err)
	}

	initialOffset, err := startingOffset(filename, fileInfo.Size(), config.Location)
	if err != nil {
		return nil, err
	}

	tailerCtx, cancel := context.WithCancel(ctx)
	fileTailer := &Tailer{
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

// startingOffset is the first byte to read. SeekEnd starts after the last newline. Every other whence uses Offset as that byte.
func startingOffset(filename string, size int64, location *SeekInfo) (int64, error) {
	if location == nil {
		return 0, nil
	}
	if location.Whence == io.SeekEnd {
		return offsetAfterLastNewline(filename, size)
	}
	return location.Offset, nil
}

// Filename is the path this tailer was started on.
func (fileTailer *Tailer) Filename() string {
	return fileTailer.filename
}

// Lines delivers each newline-terminated line. Stop closes the channel.
func (fileTailer *Tailer) Lines() <-chan *Line {
	return fileTailer.lines
}

// Dying closes when the follow has ended.
func (fileTailer *Tailer) Dying() <-chan struct{} {
	return fileTailer.dying
}

// Err is the first failure that stopped this tailer, or nil.
func (fileTailer *Tailer) Err() error {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()
	return fileTailer.err
}

// Stop cancels the follow loop, then closes Lines and Dying.
func (fileTailer *Tailer) Stop() error {
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
func (fileTailer *Tailer) closeDyingAndReleaseHandle() {
	fileTailer.followEnded.Do(func() {
		close(fileTailer.dying)
		close(fileTailer.lines)
	})
}

// recordFirstErrorAndStop keeps the first error and cancels the follow loop.
func (fileTailer *Tailer) recordFirstErrorAndStop(err error) {
	fileTailer.mu.Lock()
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.mu.Unlock()
	fileTailer.cancel()
}

// pollUntilStopped reads on each poll tick until Stop or the first recorded error.
func (fileTailer *Tailer) pollUntilStopped() {
	defer fileTailer.wg.Done()
	defer fileTailer.closeDyingAndReleaseHandle()

	pollInterval := pollIntervalOrDefault(fileTailer.config.PollInterval)

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
			fileTailer.readLinesSinceLastOffset()
		}
	}
}

// pollIntervalOrDefault turns an omitted interval into one second. A negative interval stays negative so the loop can wait for a manual read.
func pollIntervalOrDefault(pollInterval time.Duration) time.Duration {
	if pollInterval == 0 {
		return defaultPollInterval
	}
	return pollInterval
}

// readLinesSinceLastOffset opens the path and reads lines written since lastOffset.
func (fileTailer *Tailer) readLinesSinceLastOffset() {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()

	if fileTailer.stopped {
		return
	}

	fileTailer.readLinesByReopening()
}

// readLinesByReopening stats the path, then opens it to read lines past lastOffset.
// The offset is not moved back to the size from before the read, so a line appended during the read is not sent twice.
func (fileTailer *Tailer) readLinesByReopening() {
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
	// Size is taken after the read. Using the size from before the read would send an appended line twice.
	fileInfoAfterRead, statErr := openedFile.Stat()
	if statErr != nil {
		fileTailer.lastSize = fileTailer.lastOffset
		return
	}
	fileTailer.lastSize = max(fileInfoAfterRead.Size(), fileTailer.lastOffset)
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
func (fileTailer *Tailer) sendCompleteLines(reader *bufio.Reader) (int64, int64, error) {
	var completeBytes int64
	for {
		chunk, readErr := reader.ReadString('\n')

		// A chunk with no newline is not a line. A real read error drops it; EOF holds it.
		if chunk != "" && !strings.HasSuffix(chunk, "\n") {
			if readErr != nil && readErr != io.EOF {
				return completeBytes, 0, readErr
			}
			return completeBytes, int64(len(chunk)), nil
		}

		if strings.HasSuffix(chunk, "\n") {
			completeBytes += int64(len(chunk))
			if fileTailer.enqueueLine(strings.TrimRight(chunk, "\n\r")) {
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
func (fileTailer *Tailer) enqueueLine(lineText string) (followStopped bool) {
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
func (fileTailer *Tailer) recordFirstErrorAndStopWhileLocked(err error) {
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.cancel()
}

// offsetAfterLastNewline is the byte after the last newline.
// A file that does not end in a newline returns the start of that trailing fragment.
// A file with no newline returns 0.
func offsetAfterLastNewline(filename string, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}

	file, err := openFileForRead(filename)
	if err != nil {
		return 0, fmt.Errorf("could not open file %s: %w", filename, err)
	}
	defer file.Close()

	const chunkSize = 8192
	buf := make([]byte, chunkSize)
	position := size

	for position > 0 {
		chunkLength := chunkSize
		if int64(chunkLength) > position {
			chunkLength = int(position)
		}
		position -= int64(chunkLength)

		_, err := file.ReadAt(buf[:chunkLength], position)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("could not read file %s: %w", filename, err)
		}

		for byteIndex := chunkLength - 1; byteIndex >= 0; byteIndex-- {
			if buf[byteIndex] == '\n' {
				return position + int64(byteIndex) + 1, nil
			}
		}
	}

	return 0, nil
}

// openFileForReadInTest replaces openFileForRead when a test sets it. Production leaves it nil.
var openFileForReadInTest func(filename string) (*os.File, error)

// statFileInTest replaces statFile when a test sets it. Production leaves it nil.
var statFileInTest func(name string) (os.FileInfo, error)

// openFileForRead opens filename for a shared read so another process can still append, rename, or delete it.
func openFileForRead(filename string) (*os.File, error) {
	if openFileForReadInTest == nil {
		return openSharedRead(filename)
	}
	return openFileForReadInTest(filename)
}

// statFile stats name. A test that set statFileInTest receives that result instead.
func statFile(name string) (os.FileInfo, error) {
	if statFileInTest == nil {
		return os.Stat(name)
	}
	return statFileInTest(name)
}
