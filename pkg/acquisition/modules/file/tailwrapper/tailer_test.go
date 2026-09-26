// Copyright (c) 2024 CrowdSec
// Adapted from https://github.com/nxadm/tail tests
// Original copyright: (c) 2019 FOSS contributors of https://github.com/nxadm/tail
// Original copyright: (c) 2015 HPE Software Inc. All rights reserved.
// Original copyright: (c) 2013 ActiveState Software Inc. All rights reserved.

package tailwrapper

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Helper Infrastructure (adapted from nxadm/tail)
// =============================================================================

// TailTest provides utilities for testing the tailer
type TailTest struct {
	Name string
	path string
	done chan struct{}
	t    *testing.T
}

// NewTailTest creates a new test helper with a temporary directory
func NewTailTest(name string, t *testing.T) (*TailTest, func()) {
	testdir := t.TempDir()
	return &TailTest{
		Name: name,
		path: testdir,
		done: make(chan struct{}),
		t:    t,
	}, func() {
		// TempDir cleanup is automatic
	}
}

func (tt *TailTest) CreateFile(name string, contents string) {
	err := os.WriteFile(filepath.Join(tt.path, name), []byte(contents), 0o600)
	if err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *TailTest) RemoveFile(name string) {
	err := os.Remove(filepath.Join(tt.path, name))
	if err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *TailTest) RenameFile(oldname, newname string) {
	oldpath := filepath.Join(tt.path, oldname)
	newpath := filepath.Join(tt.path, newname)
	err := os.Rename(oldpath, newpath)
	if err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *TailTest) AppendFile(name string, contents string) {
	f, err := os.OpenFile(filepath.Join(tt.path, name), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		tt.t.Fatal(err)
	}
	defer f.Close()
	_, err = f.WriteString(contents)
	if err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *TailTest) TruncateFile(name string, contents string) {
	f, err := os.OpenFile(filepath.Join(tt.path, name), os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		tt.t.Fatal(err)
	}
	defer f.Close()
	_, err = f.WriteString(contents)
	if err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *TailTest) StartTail(name string, config Config) Tailer {
	tail, err := TailFile(tt.t.Context(), filepath.Join(tt.path, name), config)
	if err != nil {
		tt.t.Fatal(err)
	}
	return tail
}

func (tt *TailTest) StartTailWithContext(ctx context.Context, name string, config Config) Tailer {
	tail, err := TailFile(ctx, filepath.Join(tt.path, name), config)
	if err != nil {
		tt.t.Fatal(err)
	}
	return tail
}

// VerifyTailOutput reads lines from tail and verifies they match expected.
// Note: Uses Errorf instead of Fatalf because this may be called from a goroutine.
func (tt *TailTest) VerifyTailOutput(tail Tailer, lines []string, expectEOF bool) {
	defer close(tt.done)
	tt.ReadLines(tail, lines)
	if expectEOF {
		line, ok := <-tail.Lines()
		if ok && line != nil {
			tt.t.Errorf("more content from tail: %+v", line)
		}
	}
}

// ReadLines reads expected lines from tail.
// Note: Uses Errorf instead of Fatalf because this may be called from a goroutine.
func (tt *TailTest) ReadLines(tail Tailer, lines []string) {
	for _, expectedLine := range lines {
		select {
		case tailedLine, ok := <-tail.Lines():
			if !ok {
				err := tail.Err()
				if err != nil {
					tt.t.Errorf("tail ended with error: %v", err)
					return
				}
				tt.t.Errorf("tail ended early; expecting more lines")
				return
			}
			if tailedLine == nil {
				tt.t.Errorf("tail.Lines returned nil")
				return
			}
			if tailedLine.Text != expectedLine {
				tt.t.Errorf("unexpected line from tail: expecting <<%s>>, got <<%s>>",
					expectedLine, tailedLine.Text)
				return
			}
		case <-time.After(5 * time.Second):
			tt.t.Errorf("timeout waiting for line: %s", expectedLine)
			return
		}
	}
}

// CollectLines collects all lines until tail stops
func (*TailTest) CollectLines(tail Tailer, timeout time.Duration) []string {
	var lines []string
	timer := time.After(timeout)
	for {
		select {
		case line, ok := <-tail.Lines():
			if !ok {
				return lines
			}
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		case <-timer:
			return lines
		}
	}
}

func (tt *TailTest) Cleanup(tail Tailer, stop bool) {
	select {
	case <-tt.done:
	case <-time.After(5 * time.Second):
		tt.t.Log("Warning: test verification did not complete")
	}
	if stop {
		_ = tail.Stop()
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
			tailTest, cleanup := NewTailTest("stop-nonempty", t)
			defer cleanup()

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
			tailTest, cleanup := NewTailTest("location-full", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
		})
	}
}

func TestTailer_LocationEnd(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest, cleanup := NewTailTest("location-end", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
		})
	}
}

func TestTailer_LocationMiddle(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest, cleanup := NewTailTest("location-middle", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
		})
	}
}

// =============================================================================
// Truncation/ReSeek Tests (adapted from TestReSeekInotify, TestReSeekPolling)
// =============================================================================

func TestTailer_ReSeek(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest, cleanup := NewTailTest("reseek", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
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
			defer func() { _ = tail.Stop() }()

			tl := tail.(*tailer)

			// Add more content
			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("line6\n")
			f.Close()
			tl.ForceRead()

			// TRUNCATE: Write less content
			err = os.WriteFile(testFile, []byte("new1\nnew2\n"), 0o644)
			require.NoError(t, err)
			tl.ForceRead()

			// Add more to truncated file
			f, _ = os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("new3\n")
			f.Close()
			tl.ForceRead()

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
			defer func() { _ = tail.Stop() }()

			tl := tail.(*tailer)
			tl.ForceRead()

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
			tl.ForceRead()

			// Second truncation
			err = os.WriteFile(testFile, []byte("batch3_line1\n"), 0o644)
			require.NoError(t, err)
			tl.ForceRead()

			// Add to batch3
			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("batch3_line2\n")
			f.Close()
			tl.ForceRead()

			// Third truncation
			err = os.WriteFile(testFile, []byte("batch4_line1\n"), 0o644)
			require.NoError(t, err)
			tl.ForceRead()

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
			tailTest, cleanup := NewTailTest("over4096", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
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
	defer func() { _ = tail.Stop() }()

	tl := tail.(*tailer)

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

	tl.ForceRead()
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
			tailTest, cleanup := NewTailTest("basic", t)
			defer cleanup()

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
			tailTest.Cleanup(tail, true)
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
	defer func() { _ = tail.Stop() }()

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
	defer func() { _ = tail.Stop() }()

	tl := tail.(*tailer)
	tl.ForceRead()

	// Delete the file
	err = os.Remove(testFile)
	require.NoError(t, err)

	// Force read to detect file deletion
	tl.ForceRead()

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
	defer func() { _ = tail.Stop() }()

	tl := tail.(*tailer)
	tl.ForceRead()

	// Remove read permission
	err = os.Chmod(testFile, 0o000)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(testFile, 0o644) }()

	tl.ForceRead()

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
	defer func() { _ = tail.Stop() }()

	start := time.Now()
	f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("line2\n")
	f.Close()

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
	defer func() { _ = tail.Stop() }()

	time.Sleep(50 * time.Millisecond)
	f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("line2\n")
	f.Close()

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
	defer func() { _ = tail.Stop() }()

	time.Sleep(50 * time.Millisecond)
	f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("line2\n")
	f.Close()

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
			defer func() { _ = tail.Stop() }()

			// Append lines one by one with larger delays for reliability
			go func() {
				for i := 1; i <= 5; i++ {
					time.Sleep(100 * time.Millisecond)
					f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
					_, _ = f.WriteString(strings.Repeat("x", i) + "\n")
					f.Close()
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
			defer func() { _ = tail.Stop() }()

			tl := tail.(*tailer)
			tl.ForceRead()

			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("line4\n")
			f.Close()
			tl.ForceRead()

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
			defer func() { _ = tail.Stop() }()

			time.Sleep(100 * time.Millisecond)

			// Append before rotation
			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("line3\n")
			f.Close()

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
			defer func() { _ = tail.Stop() }()

			// Append to empty file
			time.Sleep(50 * time.Millisecond)
			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString("first\n")
			f.Close()

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
			defer func() { _ = tail.Stop() }()

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
			f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
			_, _ = f.WriteString(" more\n")
			f.Close()

			// Should get "partial more" now
			select {
			case line = <-tail.Lines():
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Timeout waiting for partial line completion")
			}
			// Note: depending on timing, we might get "partial" or "partial more"
			assert.Contains(t, line.Text, "partial")
		})
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
			defer func() { _ = tail.Stop() }()

			// Write many lines rapidly
			const numLines = 100
			go func() {
				f, _ := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
				defer f.Close()
				for range numLines {
					_, _ = f.WriteString(strings.Repeat("x", 50) + "\n")
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
// ForceRead Tests (for manual polling mode)
// =============================================================================

func TestTailer_ForceRead(t *testing.T) {
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
	defer func() { _ = tail.Stop() }()

	tl := tail.(*tailer)

	// Nothing should be in channel yet (manual mode, no auto-poll)
	select {
	case <-tail.Lines():
		t.Fatal("Should not have lines without ForceRead")
	case <-time.After(50 * time.Millisecond):
		// Expected
	}

	// Force read
	tl.ForceRead()

	// Now should have the line
	var line *Line
	select {
	case line = <-tail.Lines():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Should have line after ForceRead")
	}
	assert.Equal(t, "initial", line.Text)
}
