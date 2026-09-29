// The purpose of this file is to mimic the upstream github.com/nxadm/tail tests one to one.
// Each test here corresponds to a test in that suite. No judgment on whether these tests are
// appropiate or not.

package tail

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forceReadForTest reads once. The tailer must be in manual mode so the poll loop is not also reading.
func forceReadForTest(fileTailer *Tailer) {
	fileTailer.readLines()
}

// appendToFileInTest opens filename, appends contents, and closes it.
func appendToFileInTest(filename string, contents string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(contents)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// =============================================================================
// Test Helper Infrastructure (adapted from nxadm/tail)
// =============================================================================

// TailTest is a temp directory the file helpers write into, plus a done channel the line check closes.
type TailTest struct {
	Name string
	path string
	done chan struct{}
	test *testing.T
}

// NewTailTest makes the temp directory the file helpers write into. The test runtime removes that directory.
func NewTailTest(name string, test *testing.T) *TailTest {
	return &TailTest{
		Name: name,
		path: test.TempDir(),
		done: make(chan struct{}),
		test: test,
	}
}

// CreateFile writes contents into name under the temp directory and fails the test on error.
func (tailTest *TailTest) CreateFile(name string, contents string) {
	filePath := filepath.Join(tailTest.path, name)
	if err := os.WriteFile(filePath, []byte(contents), 0o600); err != nil {
		tailTest.test.Fatal(err)
	}
}

// RemoveFile deletes name from the temp directory and fails the test on error.
func (tailTest *TailTest) RemoveFile(name string) {
	filePath := filepath.Join(tailTest.path, name)
	if err := os.Remove(filePath); err != nil {
		tailTest.test.Fatal(err)
	}
}

// RenameFile renames a file inside the temp directory and fails the test on error.
func (tailTest *TailTest) RenameFile(oldname, newname string) {
	oldPath := filepath.Join(tailTest.path, oldname)
	newPath := filepath.Join(tailTest.path, newname)
	if err := os.Rename(oldPath, newPath); err != nil {
		tailTest.test.Fatal(err)
	}
}

// AppendFile adds contents to name in the temp directory and fails the test on error.
func (tailTest *TailTest) AppendFile(name string, contents string) {
	tailTest.writeFile(name, contents, os.O_APPEND|os.O_WRONLY)
}

// TruncateFile replaces name in the temp directory with contents and fails the test on error.
func (tailTest *TailTest) TruncateFile(name string, contents string) {
	tailTest.writeFile(name, contents, os.O_TRUNC|os.O_WRONLY)
}

// writeFile opens name in the temp directory with flag, writes contents, and fails the test on error.
func (tailTest *TailTest) writeFile(name string, contents string, flag int) {
	filePath := filepath.Join(tailTest.path, name)
	file, err := os.OpenFile(filePath, flag, 0o600)
	if err != nil {
		tailTest.test.Fatal(err)
	}
	_, writeErr := file.WriteString(contents)
	closeErr := file.Close()
	if writeErr != nil {
		tailTest.test.Fatal(writeErr)
	}
	if closeErr != nil {
		tailTest.test.Fatal(closeErr)
	}
}

// StartTail follows name in the temp directory with the test context and fails the test if the file cannot be opened.
func (tailTest *TailTest) StartTail(name string, config Config) *Tailer {
	return tailTest.StartTailWithContext(tailTest.test.Context(), name, config)
}

// StartTailWithContext follows name in the temp directory until ctx ends and fails the test if the file cannot be opened.
func (tailTest *TailTest) StartTailWithContext(ctx context.Context, name string, config Config) *Tailer {
	filePath := filepath.Join(tailTest.path, name)
	tail, err := TailFile(ctx, filePath, config)
	if err != nil {
		tailTest.test.Fatal(err)
	}
	return tail
}

// VerifyTailOutput checks lines in order, then closes the helper's done channel. It uses Errorf because callers run it in a goroutine.
func (tailTest *TailTest) VerifyTailOutput(tail *Tailer, lines []string, expectEOF bool) {
	defer close(tailTest.done)
	tailTest.ReadLines(tail, lines)
	if !expectEOF {
		return
	}
	line, ok := <-tail.Lines()
	if !ok || line == nil {
		return
	}
	tailTest.test.Errorf("more content from tail: %+v", line)
}

// ReadLines fails the test with Errorf when a line is missing, unexpected, or late. Callers may run it in a goroutine.
func (tailTest *TailTest) ReadLines(tail *Tailer, lines []string) {
	for _, expectedLine := range lines {
		select {
		case tailedLine, ok := <-tail.Lines():
			if !ok {
				tailTest.reportTailEnded(tail)
				return
			}
			if tailedLine == nil {
				tailTest.test.Errorf("tail.Lines returned nil")
				return
			}
			if tailedLine.Text != expectedLine {
				tailTest.test.Errorf("unexpected line from tail: expecting <<%s>>, got <<%s>>", expectedLine, tailedLine.Text)
				return
			}
		case <-time.After(5 * time.Second):
			tailTest.test.Errorf("timeout waiting for line: %s", expectedLine)
			return
		}
	}
}

// reportTailEnded records whether the channel closed because of a tail error or because lines ran out.
func (tailTest *TailTest) reportTailEnded(tail *Tailer) {
	if err := tail.Err(); err != nil {
		tailTest.test.Errorf("tail ended with error: %v", err)
		return
	}
	tailTest.test.Errorf("tail ended early; expecting more lines")
}

// CollectLines returns non-empty line texts until Lines closes or timeout elapses.
func (*TailTest) CollectLines(tail *Tailer, timeout time.Duration) []string {
	var lines []string
	timer := time.After(timeout)
	for {
		select {
		case line, ok := <-tail.Lines():
			if !ok {
				return lines
			}
			if line == nil || line.Text == "" {
				continue
			}
			lines = append(lines, line.Text)
		case <-timer:
			return lines
		}
	}
}

// waitForLineCheckThenStop waits until VerifyTailOutput closes done, then stops the tailer when stop is set.
func (tailTest *TailTest) waitForLineCheckThenStop(tail *Tailer, stop bool) {
	select {
	case <-tailTest.done:
	case <-time.After(5 * time.Second):
		tailTest.test.Log("Warning: test verification did not complete")
	}
	if err := tail.Stop(); err != nil {
		tailTest.test.Fatal(err)
	}
}

// =============================================================================
// Test matrix for the poll tailer.
// =============================================================================

var tailerModes = []struct {
	name string
}{
	{name: "poll"},
}

// =============================================================================
// File Existence Tests (adapted from TestMustExist)
// =============================================================================

func TestTailer_FileMustExist(t *testing.T) {
	dir := t.TempDir()
	nonExistentFile := filepath.Join(dir, "no_such_file.txt")

	// Should fail when file doesn't exist
	config := Config{
		PollInterval: 100 * time.Millisecond,
	}

	_, err := TailFile(t.Context(), nonExistentFile, config)
	require.Error(t, err, "Should error when file doesn't exist")
	assert.Contains(t, err.Error(), "could not stat file")
}

func TestTailer_FileExists(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")

	err := os.WriteFile(testFile, []byte("hello\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		PollInterval: -1,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err, "Should succeed when file exists")
	_ = tail.Stop()
}

// =============================================================================
// Stop Tests (adapted from TestStop, TestStopNonEmptyFile)
// =============================================================================

func TestTailer_Stop(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)

			// Stop should not error
			err = tail.Stop()
			require.NoError(t, err)

			// Should be dying
			select {
			case <-tail.Dying():
				// Good
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Should be dying after stop")
			}

			// Calling stop again should be safe (idempotent)
			err = tail.Stop()
			assert.NoError(t, err)
		})
	}
}

func TestTailer_StopNonEmptyFile(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("stop-nonempty", t)

			tailTest.CreateFile("test.txt", "hello\nthere\nworld\n")
			tail := tailTest.StartTail("test.txt", Config{
				PollInterval: -1,
			})

			// Stop immediately - should not panic
			err := tail.Stop()
			assert.NoError(t, err)
		})
	}
}

// =============================================================================
// Location Tests (adapted from TestLocationFull, TestLocationEnd, TestLocationMiddle)
// =============================================================================

func TestTailer_LocationFull(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("location-full", t)

			tailTest.CreateFile("test.txt", "hello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     nil, // nil means start from beginning
			}

			tail := tailTest.StartTail("test.txt", config)
			go tailTest.VerifyTailOutput(tail, []string{"hello", "world"}, false)

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

func TestTailer_LocationEnd(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("location-end", t)

			tailTest.CreateFile("test.txt", "hello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			}

			tail := tailTest.StartTail("test.txt", config)
			go tailTest.VerifyTailOutput(tail, []string{"more", "data"}, false)

			<-time.After(100 * time.Millisecond)
			tailTest.AppendFile("test.txt", "more\ndata\n")

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

func TestTailer_LocationMiddle(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("location-middle", t)
			// "hello\nworld\n" is 12 bytes
			// We want to start reading from "world\n" which is at byte 6
			// Using SeekStart with offset 6 is clearer than SeekEnd with -6
			tailTest.CreateFile("test.txt", "hello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 6, Whence: io.SeekStart}, // Start at "world\n"
			}

			tail := tailTest.StartTail("test.txt", config)
			go tailTest.VerifyTailOutput(tail, []string{"world", "more", "data"}, false)

			<-time.After(100 * time.Millisecond)
			tailTest.AppendFile("test.txt", "more\ndata\n")

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

// =============================================================================
// Truncation/ReSeek Tests (adapted from TestReSeekInotify, TestReSeekPolling)
// =============================================================================

func TestTailer_ReSeek(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("reseek", t)

			tailTest.CreateFile("test.txt", "a really long string goes here\nhello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     nil, // Start from beginning
			}

			tail := tailTest.StartTail("test.txt", config)

			expected := []string{
				"a really long string goes here", "hello", "world",
				"h311o", "w0r1d", "endofworld",
			}
			go tailTest.VerifyTailOutput(tail, expected, false)

			// Truncate and write new content
			<-time.After(200 * time.Millisecond)
			tailTest.TruncateFile("test.txt", "h311o\nw0r1d\nendofworld\n")

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

func TestTailer_TruncationDetection(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\nline5\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				PollInterval: -1, // Manual polling
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail

			// Add more content
			require.NoError(t, appendToFileInTest(testFile, "line6\n"))
			forceReadForTest(fileTailer)

			// TRUNCATE: Write less content
			err = os.WriteFile(testFile, []byte("new1\nnew2\n"), 0o644)
			require.NoError(t, err)
			forceReadForTest(fileTailer)

			// Add more to truncated file
			require.NoError(t, appendToFileInTest(testFile, "new3\n"))
			forceReadForTest(fileTailer)

			// Collect lines
			var lines []string
			done := make(chan struct{})
			go func() {
				defer close(done)
				for line := range tail.Lines() {
					if line != nil && line.Text != "" {
						lines = append(lines, line.Text)
					}
				}
			}()

			_ = tail.Stop()
			<-done

			assert.Contains(t, lines, "new1", "Should have read new1 after truncation")
			assert.Contains(t, lines, "new2", "Should have read new2 after truncation")
			assert.Contains(t, lines, "new3", "Should have read new3 after truncation")
		})
	}
}

func TestTailer_MultipleTruncations(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("batch1_line1\nbatch1_line2\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				PollInterval: -1, // Manual polling
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail
			forceReadForTest(fileTailer)

			var lines []string
			done := make(chan struct{})
			go func() {
				defer close(done)
				for line := range tail.Lines() {
					if line != nil && line.Text != "" {
						lines = append(lines, line.Text)
					}
				}
			}()

			time.Sleep(10 * time.Millisecond)

			// First truncation
			err = os.WriteFile(testFile, []byte("batch2_line1\n"), 0o644)
			require.NoError(t, err)
			forceReadForTest(fileTailer)

			// Second truncation
			err = os.WriteFile(testFile, []byte("batch3_line1\n"), 0o644)
			require.NoError(t, err)
			forceReadForTest(fileTailer)

			// Add to batch3
			require.NoError(t, appendToFileInTest(testFile, "batch3_line2\n"))
			forceReadForTest(fileTailer)

			// Third truncation
			err = os.WriteFile(testFile, []byte("batch4_line1\n"), 0o644)
			require.NoError(t, err)
			forceReadForTest(fileTailer)

			_ = tail.Stop()
			<-done

			t.Logf("Lines read: %v", lines)
			assert.Contains(t, lines, "batch2_line1", "Should handle first truncation")
			assert.Contains(t, lines, "batch4_line1", "Should handle third truncation")
		})
	}
}

// =============================================================================
// Large Line Tests (adapted from TestOver4096ByteLine)
// =============================================================================

func TestTailer_Over4096ByteLine(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("over4096", t)
			testString := strings.Repeat("a", 4097)
			tailTest.CreateFile("test.txt", "test\n"+testString+"\nhello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     nil,
			}

			tail := tailTest.StartTail("test.txt", config)
			go tailTest.VerifyTailOutput(tail, []string{"test", testString, "hello", "world"}, false)

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

func TestTailer_LargeLines(t *testing.T) {
	// Test with lines larger than bufio.Scanner limit (64KB)
	dir := t.TempDir()
	testFile := filepath.Join(dir, "large.log")

	const bufioMaxScanTokenSize = 64 * 1024
	largeLine := make([]byte, bufioMaxScanTokenSize*2) // 128KB line
	for i := range largeLine {
		largeLine[i] = byte('A' + (i % 26))
	}
	content := string(largeLine) + "\nline2\n"

	err := os.WriteFile(testFile, []byte(content), 0o644)
	require.NoError(t, err)

	config := Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail

	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tail.Lines() {
			if line != nil {
				lines = append(lines, line.Text)
			}
		}
	}()

	forceReadForTest(fileTailer)
	_ = tail.Stop()
	<-done

	require.Len(t, lines, 2, "Should have read both lines")
	assert.Len(t, lines[0], len(largeLine), "First line should be 128KB")
	assert.Equal(t, "line2", lines[1], "Second line should be line2")
	assert.NoError(t, tail.Err(), "Should handle large lines without error")
}
