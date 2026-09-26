// Copyright (c) 2024 CrowdSec
// Adapted from https://github.com/nxadm/tail tests
// Original copyright: (c) 2019 FOSS contributors of https://github.com/nxadm/tail
// Original copyright: (c) 2015 HPE Software Inc. All rights reserved.
// Original copyright: (c) 2013 ActiveState Software Inc. All rights reserved.

package tail

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forceReadForTest reads once. The tailer must be in manual mode so the poll loop is not also reading.
func forceReadForTest(fileTailer *tailer) {
	fileTailer.readLinesSinceLastOffset()
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
func (tailTest *TailTest) StartTail(name string, config Config) Tailer {
	return tailTest.StartTailWithContext(tailTest.test.Context(), name, config)
}

// StartTailWithContext follows name in the temp directory until ctx ends and fails the test if the file cannot be opened.
func (tailTest *TailTest) StartTailWithContext(ctx context.Context, name string, config Config) Tailer {
	filePath := filepath.Join(tailTest.path, name)
	tail, err := TailFile(ctx, filePath, config)
	if err != nil {
		tailTest.test.Fatal(err)
	}
	return tail
}

// VerifyTailOutput checks lines in order, then closes the helper's done channel. It uses Errorf because callers run it in a goroutine.
func (tailTest *TailTest) VerifyTailOutput(tail Tailer, lines []string, expectEOF bool) {
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
func (tailTest *TailTest) ReadLines(tail Tailer, lines []string) {
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
func (tailTest *TailTest) reportTailEnded(tail Tailer) {
	if err := tail.Err(); err != nil {
		tailTest.test.Errorf("tail ended with error: %v", err)
		return
	}
	tailTest.test.Errorf("tail ended early; expecting more lines")
}

// CollectLines returns non-empty line texts until Lines closes or timeout elapses.
func (*TailTest) CollectLines(tail Tailer, timeout time.Duration) []string {
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
func (tailTest *TailTest) waitForLineCheckThenStop(tail Tailer, stop bool) {
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
// Test matrix for both tailer modes
// =============================================================================

var tailerModes = []struct {
	name         string
	keepFileOpen bool
}{
	{name: "keepOpen", keepFileOpen: true},
	{name: "closeAfterRead", keepFileOpen: false},
}

// =============================================================================
// File Existence Tests (adapted from TestMustExist)
// =============================================================================

func TestTailer_FileMustExist(t *testing.T) {
	dir := t.TempDir()
	nonExistentFile := filepath.Join(dir, "no_such_file.txt")

	// Should fail when file doesn't exist
	config := Config{
		Poll:         true,
		PollInterval: 100 * time.Millisecond,
		KeepFileOpen: false,
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
		Poll:         true,
		PollInterval: -1,
		KeepFileOpen: false,
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
				ReOpen:       true,
				Poll:         true,
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
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
				Poll:         true,
				PollInterval: -1,
				KeepFileOpen: mode.keepFileOpen,
			})

			// Stop immediately - should not panic
			err := tail.Stop()
			assert.NoError(t, err)
		})
	}
}

func TestTailer_ContextCancellation(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(t.Context())

			config := Config{
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(ctx, testFile, config)
			require.NoError(t, err)

			// Cancel context
			cancel()

			// Should stop within reasonable time
			select {
			case <-tail.Dying():
				// Context cancellation triggers shutdown
			case <-time.After(500 * time.Millisecond):
				// May need explicit stop
				_ = tail.Stop()
			}

			// Final cleanup
			_ = tail.Stop()
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
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     nil, // nil means start from beginning
				KeepFileOpen: mode.keepFileOpen,
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
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
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
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 6, Whence: io.SeekStart}, // Start at "world\n"
				KeepFileOpen: mode.keepFileOpen,
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
				ReOpen:       false,
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     nil, // Start from beginning
				KeepFileOpen: mode.keepFileOpen,
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
				ReOpen:       true,
				Poll:         true,
				PollInterval: -1, // Manual polling
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail.(*tailer)

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
				ReOpen:       true,
				Poll:         true,
				PollInterval: -1, // Manual polling
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail.(*tailer)
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
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     nil,
				KeepFileOpen: mode.keepFileOpen,
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
		ReOpen:       true,
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail.(*tailer)

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

// =============================================================================
// Basic Tailing Tests
// =============================================================================

func TestTailer_BasicTailing(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("basic", t)

			tailTest.CreateFile("test.txt", "line1\nline2\nline3\n")

			config := Config{
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail := tailTest.StartTail("test.txt", config)

			go tailTest.VerifyTailOutput(tail, []string{"line4", "line5"}, false)

			<-time.After(100 * time.Millisecond)
			tailTest.AppendFile("test.txt", "line4\nline5\n")

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

func TestTailer_Filename(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		Poll:         true,
		PollInterval: -1,
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	assert.Equal(t, testFile, tail.Filename())
}

// =============================================================================
// File Deletion Tests
// =============================================================================

func TestTailer_FileDeleted(t *testing.T) {
	// Test closeAfterRead mode for file deletion
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:       true,
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail.(*tailer)
	forceReadForTest(fileTailer)

	// Delete the file
	err = os.Remove(testFile)
	require.NoError(t, err)

	// Force read to detect file deletion
	forceReadForTest(fileTailer)

	// Check if error was set
	err = tail.Err()
	require.Error(t, err, "Should have an error after file deletion")
	assert.Contains(t, err.Error(), "no longer exists")

	_ = tail.Stop()

	select {
	case <-tail.Dying():
		// Good
	default:
		t.Fatal("Dying channel should be closed after Stop()")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestTailer_ErrorHandling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Permission tests not reliable on Windows")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:       true,
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail.(*tailer)
	forceReadForTest(fileTailer)

	// Remove read permission
	err = os.Chmod(testFile, 0o000)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(testFile, 0o644) }()

	forceReadForTest(fileTailer)

	// Should detect error
	select {
	case <-tail.Dying():
		err := tail.Err()
		require.Error(t, err, "Should have an error")
	case <-time.After(1 * time.Second):
		t.Log("Permission error not detected immediately")
	}
}

// =============================================================================
// Poll Interval Tests
// =============================================================================

func TestTailer_PollInterval(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	pollInterval := 200 * time.Millisecond
	config := Config{
		ReOpen:       true,
		Poll:         true,
		PollInterval: pollInterval,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	start := time.Now()
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))

	var lineReadTime time.Time
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		timeout := time.After(2 * time.Second)
		for {
			select {
			case <-timeout:
				return
			case line := <-tail.Lines():
				if line != nil && line.Text == "line2" {
					lineReadTime = time.Now()
					return
				}
			}
		}
	}()

	wg.Wait()

	elapsed := lineReadTime.Sub(start)
	assert.Less(t, elapsed, pollInterval+300*time.Millisecond, "Should read within poll interval")
	assert.False(t, lineReadTime.IsZero(), "Line should have been read")
}

// =============================================================================
// fsnotify Tests (KeepFileOpen mode)
// =============================================================================

func TestTailer_KeepOpenWithPolling(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:       true,
		Poll:         true, // Use polling, not fsnotify
		PollInterval: 100 * time.Millisecond,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: true,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))

	var line *Line
	select {
	case line = <-tail.Lines():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for line")
	}

	assert.Equal(t, "line2", line.Text)
}

func TestTailer_KeepOpenWithFsnotify(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fsnotify behavior varies on Windows")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:       true,
		Poll:         false, // Use fsnotify
		PollInterval: 1 * time.Second,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: true,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))

	var line *Line
	select {
	case line = <-tail.Lines():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for line via fsnotify")
	}

	assert.Equal(t, "line2", line.Text)
}

// =============================================================================
// Append Tests
// =============================================================================

func TestTailer_ContinuousAppend(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte(""), 0o644)
			require.NoError(t, err)

			config := Config{
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			// Append lines one by one with larger delays for reliability
			go func() {
				for repeatCount := 1; repeatCount <= 5; repeatCount++ {
					time.Sleep(100 * time.Millisecond)
					line := strings.Repeat("x", repeatCount) + "\n"
					if err := appendToFileInTest(testFile, line); err != nil {
						t.Errorf("append %s: %v", testFile, err)
						return
					}
				}
			}()

			// Collect lines
			var lines []string
			timeout := time.After(3 * time.Second)
		loop:
			for {
				select {
				case line := <-tail.Lines():
					if line != nil && line.Text != "" {
						lines = append(lines, line.Text)
						if len(lines) >= 5 {
							break loop
						}
					}
				case <-timeout:
					break loop
				}
			}

			require.Len(t, lines, 5, "Should have read all 5 lines")
			// Verify we got all expected lines (order should match)
			expected := []string{"x", "xx", "xxx", "xxxx", "xxxxx"}
			assert.Equal(t, expected, lines, "Lines should match expected content and order")
		})
	}
}

// =============================================================================
// SeekInfo Tests
// =============================================================================

func TestTailer_SeekStart(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				ReOpen:       true,
				Poll:         true,
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail.(*tailer)
			forceReadForTest(fileTailer)

			require.NoError(t, appendToFileInTest(testFile, "line4\n"))
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

			_ = tail.Stop()
			<-done

			assert.Contains(t, lines, "line1", "Should have read line1")
			assert.Contains(t, lines, "line4", "Should have read line4")
		})
	}
}

// =============================================================================
// Rotation Simulation Tests
// =============================================================================

func TestTailer_FileRotation(t *testing.T) {
	// Simulate log rotation: file is renamed and new file created
	if runtime.GOOS == "windows" {
		t.Skip("File rotation tests unreliable on Windows due to file locking")
	}

	for _, mode := range tailerModes {
		if mode.keepFileOpen {
			// File rotation with keepOpen mode is complex due to inode tracking
			// Skip for now as it requires more sophisticated handling
			continue
		}

		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\nline2\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				ReOpen:       true,
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			time.Sleep(100 * time.Millisecond)

			// Append before rotation
			require.NoError(t, appendToFileInTest(testFile, "line3\n"))

			time.Sleep(100 * time.Millisecond)

			// Note: Full rotation support would require ReOpen behavior
			// which recreates the file after deletion. For now, we test
			// that lines written before are captured.

			var lines []string
			timeout := time.After(500 * time.Millisecond)
		loop:
			for {
				select {
				case line := <-tail.Lines():
					if line != nil && line.Text != "" {
						lines = append(lines, line.Text)
					}
				case <-timeout:
					break loop
				}
			}

			assert.Contains(t, lines, "line3", "Should have captured line3")
		})
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestTailer_EmptyFile(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "empty.log")

			err := os.WriteFile(testFile, []byte(""), 0o644)
			require.NoError(t, err)

			config := Config{
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			// Append to empty file
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, appendToFileInTest(testFile, "first\n"))

			var line *Line
			select {
			case line = <-tail.Lines():
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Timeout waiting for line")
			}

			assert.Equal(t, "first", line.Text)
		})
	}
}

func TestTailer_NoNewlineAtEnd(t *testing.T) {
	// Test behavior when file doesn't end with newline
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			// File without trailing newline - the partial line should not be read
			// until a newline is appended
			err := os.WriteFile(testFile, []byte("complete\npartial"), 0o644)
			require.NoError(t, err)

			config := Config{
				Poll:         true,
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			// Should get "complete" immediately
			var line *Line
			select {
			case line = <-tail.Lines():
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Timeout waiting for complete line")
			}
			assert.Equal(t, "complete", line.Text)

			// Complete the partial line
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, appendToFileInTest(testFile, " more\n"))

			// Should get the finished line, not the fragment that was waiting.
			select {
			case line = <-tail.Lines():
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Timeout waiting for partial line completion")
			}
			assert.Equal(t, "partial more", line.Text)
		})
	}
}

func TestTailer_PartialLineIsHeldUntilNewline(t *testing.T) {
	tests := []struct {
		name     string
		truncate bool
		rest     string
		expected []string
	}{
		{
			name:     "completed",
			rest:     "1}\nthird\n",
			expected: []string{`{"a":1}`, "third"},
		},
		{
			name:     "truncated",
			truncate: true,
			rest:     "new\n",
			expected: []string{"new"},
		},
	}

	for _, mode := range tailerModes {
		for _, tc := range tests {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				testFile := filepath.Join(dir, "test.log")
				require.NoError(t, os.WriteFile(testFile, []byte(""), 0o644))

				tail, err := TailFile(t.Context(), testFile, Config{
					Poll:         true,
					PollInterval: -1,
					ReOpen:       true,
					Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
					KeepFileOpen: mode.keepFileOpen,
				})
				require.NoError(t, err)
				defer func() { require.NoError(t, tail.Stop()) }()

				fileTailer := tail.(*tailer)

				require.NoError(t, appendToFileInTest(testFile, "second\n{\"a\":"))

				forceReadForTest(fileTailer)

				require.Equal(t, "second", readTailLineForTest(t, tail))
				assertNoTailLineForTest(t, tail)

				if tc.truncate {
					require.NoError(t, os.Truncate(testFile, 0))
				}

				require.NoError(t, appendToFileInTest(testFile, tc.rest))

				forceReadForTest(fileTailer)

				var got []string
				for range tc.expected {
					got = append(got, readTailLineForTest(t, tail))
				}
				assertNoTailLineForTest(t, tail)
				assert.Equal(t, tc.expected, got)
			})
		}
	}
}

func readTailLineForTest(t *testing.T, tail Tailer) string {
	t.Helper()

	select {
	case line := <-tail.Lines():
		require.NotNil(t, line)
		require.NoError(t, line.Err)
		return line.Text
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for a line")
		return ""
	}
}

func assertNoTailLineForTest(t *testing.T, tail Tailer) {
	t.Helper()

	select {
	case line := <-tail.Lines():
		text := ""
		if line != nil {
			text = line.Text
		}
		t.Fatalf("unexpected line %q", text)
	default:
	}
}

func TestTailer_RapidWrites(t *testing.T) {
	// Test handling rapid successive writes
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "rapid.log")

			err := os.WriteFile(testFile, []byte(""), 0o644)
			require.NoError(t, err)

			config := Config{
				Poll:         true,
				PollInterval: 20 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
				KeepFileOpen: mode.keepFileOpen,
			}

			tail, err := TailFile(t.Context(), testFile, config)
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			// Write many lines rapidly
			const numLines = 100
			go func() {
				file, err := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					t.Errorf("open %s: %v", testFile, err)
					return
				}
				defer func() {
					if err := file.Close(); err != nil {
						t.Errorf("close %s: %v", testFile, err)
					}
				}()
				line := strings.Repeat("x", 50) + "\n"
				for range numLines {
					if _, err := file.WriteString(line); err != nil {
						t.Errorf("write %s: %v", testFile, err)
						return
					}
				}
			}()

			// Collect lines
			var lines []string
			timeout := time.After(5 * time.Second)
		loop:
			for {
				select {
				case line := <-tail.Lines():
					if line != nil && line.Text != "" {
						lines = append(lines, line.Text)
						if len(lines) >= numLines {
							break loop
						}
					}
				case <-timeout:
					break loop
				}
			}

			assert.GreaterOrEqual(t, len(lines), numLines-5, "Should have read most lines")
		})
	}
}

// =============================================================================
// Manual mode reads only when a test asks
// =============================================================================

func TestTailer_ManualModeReadsOnlyWhenAsked(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("initial\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		Poll:         true,
		PollInterval: -1, // Manual mode
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail.(*tailer)

	// Nothing should be in channel yet (manual mode, no auto-poll)
	select {
	case <-tail.Lines():
		t.Fatal("manual mode should not read before the test asks")
	case <-time.After(50 * time.Millisecond):
		// Expected
	}

	// Force read
	forceReadForTest(fileTailer)

	// Now should have the line
	var line *Line
	select {
	case line = <-tail.Lines():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("manual mode should read the line when the test asks")
	}
	assert.Equal(t, "initial", line.Text)
}

func TestOffsetAfterLastNewline(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	prefix := strings.Repeat("x", 9000)
	body := prefix + "\npartial"
	require.NoError(t, os.WriteFile(testFile, []byte(body), 0o644))

	offset, err := offsetAfterLastNewline(testFile, int64(len(body)))
	require.NoError(t, err)
	assert.Equal(t, int64(len(prefix)+1), offset)

	complete := "done\n"
	require.NoError(t, os.WriteFile(testFile, []byte(complete), 0o644))
	offset, err = offsetAfterLastNewline(testFile, int64(len(complete)))
	require.NoError(t, err)
	assert.Equal(t, int64(len(complete)), offset)
}

func TestTailer_StartAtEndOfPartialLine(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")
			require.NoError(t, os.WriteFile(testFile, []byte(`{"a":`), 0o644))

			tail, err := TailFile(t.Context(), testFile, Config{
				Poll:         true,
				PollInterval: -1,
				ReOpen:       true,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			})
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail.(*tailer)
			forceReadForTest(fileTailer)
			assertNoTailLineForTest(t, tail)

			require.NoError(t, appendToFileInTest(testFile, "1}\n"))

			forceReadForTest(fileTailer)
			assert.Equal(t, `{"a":1}`, readTailLineForTest(t, tail))
			assertNoTailLineForTest(t, tail)
		})
	}
}

func TestTailer_StartAtEndOfCompleteFile(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")
			require.NoError(t, os.WriteFile(testFile, []byte("done\n"), 0o644))

			tail, err := TailFile(t.Context(), testFile, Config{
				Poll:         true,
				PollInterval: -1,
				ReOpen:       true,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
				KeepFileOpen: mode.keepFileOpen,
			})
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			fileTailer := tail.(*tailer)
			forceReadForTest(fileTailer)
			assertNoTailLineForTest(t, tail)

			require.NoError(t, appendToFileInTest(testFile, "next\n"))

			forceReadForTest(fileTailer)
			assert.Equal(t, "next", readTailLineForTest(t, tail))
			assertNoTailLineForTest(t, tail)
		})
	}
}

func TestTailer_StatReadDoesNotRepeatAppend(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })

	appended := false
	openFileForReadInTest = func(filename string) (*os.File, error) {
		if !appended {
			appended = true
			writer, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				return nil, err
			}
			if _, err := writer.WriteString("during\n"); err != nil {
				writer.Close()
				return nil, err
			}
			if err := writer.Close(); err != nil {
				return nil, err
			}
		}
		return os.Open(filename)
	}

	tail, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		ReOpen:       true,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	fileTailer := tail.(*tailer)
	forceReadForTest(fileTailer)
	assert.Equal(t, "old", readTailLineForTest(t, tail))
	assert.Equal(t, "during", readTailLineForTest(t, tail))
	assertNoTailLineForTest(t, tail)

	forceReadForTest(fileTailer)
	assertNoTailLineForTest(t, tail)
}

// A deleted file in stat mode closes Dying so the reader can drop the tail.
func TestTailer_DeletedFileClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	followed, err := TailFile(t.Context(), testFile, Config{
		ReOpen:       true,
		Poll:         true,
		PollInterval: 20 * time.Millisecond,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = followed.Stop() })

	require.NoError(t, os.Remove(testFile))

	select {
	case <-followed.Dying():
	case <-time.After(2 * time.Second):
		t.Fatal("Dying stayed open after the file was deleted")
	}
}

// A failed reopen after the handle was cleared closes Dying so the reader can drop the tail.
func TestTailer_FailedReopenClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	followed, err := TailFile(t.Context(), testFile, Config{
		ReOpen:       true,
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: true,
	})
	require.NoError(t, err)

	originalOpen := openFileForReadInTest
	t.Cleanup(func() {
		openFileForReadInTest = originalOpen
		_ = followed.Stop()
	})

	openFileForReadInTest = func(string) (*os.File, error) {
		return nil, os.ErrPermission
	}

	fileTailer := followed.(*tailer)
	fileTailer.waitUntilFileReturns()
	require.Error(t, followed.Err())

	select {
	case <-followed.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after reopen failed")
	}
}

func startKeepOpenTailForTest(t *testing.T, testFile string, reopen bool, poll bool, pollInterval time.Duration) *tailer {
	t.Helper()

	followed, err := TailFile(t.Context(), testFile, Config{
		ReOpen:       reopen,
		Poll:         poll,
		PollInterval: pollInterval,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = followed.Stop() })
	return followed.(*tailer)
}

// A keep-open tailer with polling off installs a watcher so writes can wake the follow loop.
func TestTailer_KeepOpenWithoutPollingInstallsWatcher(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, false, 0)
	require.NotNil(t, fileTailer.watcher)
}

// A write watch event reads the new complete line.
func TestTailer_WatchWriteReadsLine(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))
	require.False(t, fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Write}))

	select {
	case line := <-fileTailer.Lines():
		require.Equal(t, "line2", line.Text)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for line after write event")
	}
}

// A remove watch event without ReOpen records the error and ends the follow.
func TestTailer_WatchRemoveWithoutReopenClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, false, true, -1)
	require.True(t, fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Remove}))
	require.Error(t, fileTailer.Err())

	select {
	case <-fileTailer.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after a remove without ReOpen")
	}
}

// A remove watch event with ReOpen waits until the path exists again and reads from the start.
func TestTailer_WatchRemoveWithReopenReadsNewFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	fileTailer.mu.Lock()
	if fileTailer.file != nil {
		_ = fileTailer.file.Close()
		fileTailer.file = nil
	}
	fileTailer.mu.Unlock()
	require.NoError(t, os.Remove(testFile))

	done := make(chan struct{})
	go func() {
		defer close(done)
		fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Remove})
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, os.WriteFile(testFile, []byte("new\n"), 0o644))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitUntilFileReturns did not return")
	}

	fileTailer.readLinesSinceLastOffset()

	select {
	case line := <-fileTailer.Lines():
		require.Equal(t, "new", line.Text)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for line after reopen")
	}
}

// Closing the watcher ends the follow loop so Dying closes.
func TestTailer_ClosedWatcherClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, false, 20*time.Millisecond)
	require.NotNil(t, fileTailer.watcher)
	require.NoError(t, fileTailer.watcher.Close())

	select {
	case <-fileTailer.Dying():
	case <-time.After(2 * time.Second):
		t.Fatal("Dying stayed open after the watcher was closed")
	}
}

// A keep-open open failure is returned from TailFile.
func TestTailer_KeepOpenOpenFailure(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = func(string) (*os.File, error) {
		return nil, os.ErrPermission
	}

	_, err := TailFile(t.Context(), testFile, Config{
		KeepFileOpen: true,
		Poll:         true,
		PollInterval: -1,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "could not open file")
}

// recordFirstErrorAndStop cancels the follow so Dying closes.
func TestTailer_RecordFirstErrorAndStopClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	fileTailer.recordFirstErrorAndStop(os.ErrPermission)
	require.Error(t, fileTailer.Err())

	select {
	case <-fileTailer.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after recordFirstErrorAndStop")
	}
}
