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

	"github.com/fsnotify/fsnotify"
)

const (
	defaultPollInterval = 1 * time.Second
)

// tailer follows one file and sends each newline-terminated line.
// KeepFileOpen keeps the handle open and watches for writes. Otherwise each pass opens, reads, and closes.
type tailer struct {
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

	// Open only while KeepFileOpen is set.
	file    *os.File
	reader  *bufio.Reader
	watcher *fsnotify.Watcher

	// lastOffset is the next byte to read. lastSize is the size after the previous pass.
	lastOffset int64
	lastSize   int64
}

// TailFile starts following filename. A missing file is an error. SeekEnd starts after the last newline.
func TailFile(ctx context.Context, filename string, config Config) (*tailer, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("could not stat file %s: %w", filename, err)
	}

	initialOffset, err := startingOffset(filename, fileInfo.Size(), config.Location)
	if err != nil {
		return nil, err
	}

	tailerCtx, cancel := context.WithCancel(ctx)
	fileTailer := &tailer{
		filename:   filename,
		config:     config,
		lines:      make(chan *Line, 100),
		dying:      make(chan struct{}),
		done:       tailerCtx.Done(),
		cancel:     cancel,
		lastOffset: initialOffset,
		lastSize:   fileInfo.Size(),
	}

	if config.KeepFileOpen {
		err = fileTailer.openFileAtOffsetAndWatch()
	}
	if err != nil {
		cancel()
		return nil, err
	}

	fileTailer.wg.Add(1)
	go fileTailer.pollOrWatchUntilStopped()

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

// openFileAtOffsetAndWatch opens the file at lastOffset and, unless polling, watches it for writes.
func (fileTailer *tailer) openFileAtOffsetAndWatch() error {
	// Open and seek first so a bad path does not leave a watcher behind.
	file, err := openFileForRead(fileTailer.filename)
	if err != nil {
		return fmt.Errorf("could not open file %s: %w", fileTailer.filename, err)
	}
	fileTailer.file = file

	if _, err := fileTailer.file.Seek(fileTailer.lastOffset, io.SeekStart); err != nil {
		fileTailer.file.Close()
		return fmt.Errorf("could not seek in file %s: %w", fileTailer.filename, err)
	}

	fileTailer.reader = bufio.NewReader(fileTailer.file)

	// Poll mode notices writes on its own ticker.
	if fileTailer.config.Poll {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fileTailer.file.Close()
		return fmt.Errorf("could not create fsnotify watcher: %w", err)
	}
	if err := watcher.Add(fileTailer.filename); err != nil {
		watcher.Close()
		fileTailer.file.Close()
		return fmt.Errorf("could not watch file %s: %w", fileTailer.filename, err)
	}
	fileTailer.watcher = watcher

	return nil
}

// Filename is the path this tailer was started on.
func (fileTailer *tailer) Filename() string {
	return fileTailer.filename
}

// Lines delivers each newline-terminated line. Stop closes the channel.
func (fileTailer *tailer) Lines() <-chan *Line {
	return fileTailer.lines
}

// Dying closes when the follow has ended.
func (fileTailer *tailer) Dying() <-chan struct{} {
	return fileTailer.dying
}

// Err is the first failure that stopped this tailer, or nil.
func (fileTailer *tailer) Err() error {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()
	return fileTailer.err
}

// Stop cancels the follow loop, then closes Lines and Dying.
func (fileTailer *tailer) Stop() error {
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

// closeDyingAndReleaseHandle closes Dying and Lines once so the reader can drop the tail, then drops the open handle.
func (fileTailer *tailer) closeDyingAndReleaseHandle() {
	fileTailer.followEnded.Do(func() {
		close(fileTailer.dying)
		close(fileTailer.lines)
		fileTailer.mu.Lock()
		fileTailer.closeWatcherAndFile()
		fileTailer.mu.Unlock()
	})
}

// closeWatcherAndFile releases the watcher and the kept-open file.
func (fileTailer *tailer) closeWatcherAndFile() {
	if fileTailer.watcher != nil {
		fileTailer.watcher.Close()
		fileTailer.watcher = nil
	}
	if fileTailer.file != nil {
		fileTailer.file.Close()
		fileTailer.file = nil
	}
}

// recordFirstErrorAndStop keeps the first error and cancels the follow loop.
func (fileTailer *tailer) recordFirstErrorAndStop(err error) {
	fileTailer.mu.Lock()
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.mu.Unlock()
	fileTailer.cancel()
}

// pollOrWatchUntilStopped reads on each poll tick and, when a watcher is set, on write and remove events.
func (fileTailer *tailer) pollOrWatchUntilStopped() {
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

	var watcherEvents <-chan fsnotify.Event
	var watcherErrors <-chan error
	if watchEventsInTest != nil {
		watcherEvents = watchEventsInTest
	} else if fileTailer.watcher != nil {
		watcherEvents = fileTailer.watcher.Events
		watcherErrors = fileTailer.watcher.Errors
	}

	for {
		select {
		case <-fileTailer.done:
			return

		case <-ticker.C:
			fileTailer.readLinesSinceLastOffset()

		case event, ok := <-watcherEvents:
			if !ok {
				return
			}
			if fileTailer.readAfterWatchEvent(event) {
				return
			}

		case watchErr, ok := <-watcherErrors:
			if !ok {
				return
			}
			fileTailer.recordFirstErrorAndStop(fmt.Errorf("fsnotify error: %w", watchErr))
			return
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

// readAfterWatchEvent reads after a write or create. A remove reopens from the start when ReOpen is set, and stops the follow otherwise.
// stopFollow is true when the file was removed and must not be reopened.
func (fileTailer *tailer) readAfterWatchEvent(event fsnotify.Event) (stopFollow bool) {
	if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
		fileTailer.readLinesSinceLastOffset()
	}
	if event.Op&fsnotify.Remove == 0 {
		return false
	}
	if fileTailer.config.ReOpen {
		fileTailer.waitUntilFileReturns()
		return false
	}
	fileTailer.recordFirstErrorAndStop(fmt.Errorf("file %s was removed", fileTailer.filename))
	return true
}

// readLinesSinceLastOffset reads lines written since lastOffset, using the open handle or a fresh open.
func (fileTailer *tailer) readLinesSinceLastOffset() {
	fileTailer.mu.Lock()
	defer fileTailer.mu.Unlock()

	if fileTailer.stopped {
		return
	}

	if fileTailer.config.KeepFileOpen {
		fileTailer.readLinesFromOpenFile()
		return
	}
	fileTailer.readLinesByReopening()
}

// readLinesFromOpenFile reads the kept-open handle. A shrink reopens the file from the start.
func (fileTailer *tailer) readLinesFromOpenFile() {
	fileInfo, err := fileTailer.file.Stat()
	if err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error statting file %s: %w", fileTailer.filename, err))
		return
	}

	// A shrink is a truncation. Read the replacement file from the first byte.
	currentSize := fileInfo.Size()
	if currentSize < fileTailer.lastSize {
		fileTailer.reopenAtOffset(0)
		fileTailer.lastSize = 0
	}

	fileTailer.emitCompleteLinesFromOpenReader()
	fileTailer.lastSize = currentSize
}

// readLinesByReopening stats the path, then opens it to read lines past lastOffset.
// The offset is not moved back to the size from before the read, so a line appended during the read is not sent twice.
func (fileTailer *tailer) readLinesByReopening() {
	fileInfo, err := os.Stat(fileTailer.filename)
	if os.IsNotExist(err) {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("file %s no longer exists", fileTailer.filename))
		return
	}
	if err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error statting file %s: %w", fileTailer.filename, err))
		return
	}

	truncated := fileInfo.Size() < fileTailer.lastSize
	if truncated {
		fileTailer.lastOffset = 0
	}

	if !fileNeedsAnotherRead(fileInfo.Size(), fileTailer.lastOffset, truncated) {
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

// fileNeedsAnotherRead is true when the file was truncated or grew past the last byte already sent.
func fileNeedsAnotherRead(size int64, lastOffset int64, truncated bool) bool {
	if truncated {
		return true
	}
	return size > lastOffset
}

// emitCompleteLinesFromOpenReader sends complete lines from the kept-open reader.
// A fragment at EOF is not a line; the handle seeks back to the start of that fragment.
func (fileTailer *tailer) emitCompleteLinesFromOpenReader() {
	_, pendingBytes, readErr := fileTailer.sendCompleteLines(fileTailer.reader)
	if readErr != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error reading file %s: %w", fileTailer.filename, readErr))
		return
	}

	// The fragment stays in front of the offset until a later read sees its newline.
	if pendingBytes > 0 {
		err := fileTailer.seekBackBeforePendingFragment(pendingBytes)
		if err != nil {
			fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error rewinding partial line in %s: %w", fileTailer.filename, err))
		}
		return
	}

	filePosition, seekErr := fileTailer.file.Seek(0, io.SeekCurrent)
	if seekErr != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error seeking in file %s: %w", fileTailer.filename, seekErr))
		return
	}
	fileTailer.lastOffset = filePosition - int64(fileTailer.reader.Buffered())
}

// seekBackBeforePendingFragment moves the kept-open handle to the start of a fragment ReadString already consumed.
func (fileTailer *tailer) seekBackBeforePendingFragment(pendingBytes int64) error {
	filePosition, err := fileTailer.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	nextOffset := max(filePosition-int64(fileTailer.reader.Buffered())-pendingBytes, 0)

	if _, err := fileTailer.file.Seek(nextOffset, io.SeekStart); err != nil {
		return err
	}

	fileTailer.reader = bufio.NewReader(fileTailer.file)
	fileTailer.lastOffset = nextOffset
	return nil
}

// sendCompleteLines sends chunks that end with a newline.
// completeBytes counts those chunks. pendingBytes is a trailing fragment at EOF and is not sent.
func (fileTailer *tailer) sendCompleteLines(reader *bufio.Reader) (int64, int64, error) {
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
func (fileTailer *tailer) enqueueLine(lineText string) (followStopped bool) {
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

// reopenAtOffset replaces the kept-open handle and continues at offset.
func (fileTailer *tailer) reopenAtOffset(offset int64) {
	if fileTailer.file != nil {
		fileTailer.file.Close()
	}

	file, err := openFileForRead(fileTailer.filename)
	if err != nil {
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error reopening file %s: %w", fileTailer.filename, err))
		return
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		file.Close()
		fileTailer.recordFirstErrorAndStopWhileLocked(fmt.Errorf("error seeking in file %s: %w", fileTailer.filename, err))
		return
	}

	fileTailer.file = file
	fileTailer.reader = bufio.NewReader(file)
	fileTailer.lastOffset = offset
}

// waitUntilFileReturns blocks until filename exists again, then reads it from the start.
func (fileTailer *tailer) waitUntilFileReturns() {
	// Close the removed path before waiting, so the recreated file can be opened.
	fileTailer.mu.Lock()
	if fileTailer.file != nil {
		fileTailer.file.Close()
		fileTailer.file = nil
	}
	fileTailer.mu.Unlock()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-fileTailer.done:
			return
		case <-ticker.C:
			fileInfo, err := os.Stat(fileTailer.filename)
			if err != nil {
				continue
			}
			// The path is back. Read it from the first byte and watch the new file.
			fileTailer.mu.Lock()
			fileTailer.reopenAtOffset(0)
			fileTailer.lastSize = fileInfo.Size()
			if fileTailer.watcher != nil {
				_ = fileTailer.watcher.Add(fileTailer.filename)
			}
			fileTailer.mu.Unlock()
			return
		}
	}
}

// recordFirstErrorAndStopWhileLocked keeps the first error and cancels the loop.
// The caller holds mu. The lock is released around cancel so the follow loop can take it.
func (fileTailer *tailer) recordFirstErrorAndStopWhileLocked(err error) {
	if fileTailer.err == nil {
		fileTailer.err = err
	}
	fileTailer.mu.Unlock()
	fileTailer.cancel()
	fileTailer.mu.Lock()
}

// offsetAfterLastNewline is the byte after the last newline.
// A file that does not end in a newline returns the start of that trailing fragment.
// A file with no newline returns 0.
func offsetAfterLastNewline(filename string, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}

	file, err := os.Open(filename)
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

// watchEventsInTest replaces the follow loop's fsnotify Events channel when a test sets it. Production leaves it nil.
var watchEventsInTest <-chan fsnotify.Event

// openFileForRead opens filename for a shared read so another process can still append.
func openFileForRead(filename string) (*os.File, error) {
	if openFileForReadInTest == nil {
		return os.Open(filename)
	}
	return openFileForReadInTest(filename)
}
