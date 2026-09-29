// The purpose of this file is to mimic the upstream github.com/nxadm/tail tests one to one.
// No judgment on whether these tests are
// appropriate or not. Some of the original tests have been replaced with improved versions in polltail_tail_test.go
// and others removed because polltail is simpler and some behaviors won't apply.

package polltail

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TailFile on a path that is not there returns an error that says the file could not be stat'd.
func TestPollTail_FileMustExist(t *testing.T) {
	// TailFile on a missing path fails.
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

// =============================================================================
// Stop Tests (adapted from TestStop, TestStopNonEmptyFile)
// =============================================================================

// Stop returns no error and closes Dying. A second Stop also returns no error.
func TestPollTail_Stop(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start a tail, then stop it twice.
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

			// Stop closes Dying. A second Stop also returns no error.
			err = tail.Stop()
			require.NoError(t, err)

			select {
			case <-tail.Dying():
				// Good
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Should be dying after stop")
			}

			err = tail.Stop()
			assert.NoError(t, err)
		})
	}
}

// =============================================================================
// Location Tests (adapted from TestLocationMiddle)
// =============================================================================

// Starting at byte 6 skips hello. world, then the appended more and data, arrive in that order.
func TestPollTail_LocationMiddle(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start in the middle of the file, past the first line.
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

			// Append two lines. They follow the line the offset landed on.
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

// The three lines already in the file arrive, then a shrink is read from the start, so h311o, w0r1d, and endofworld follow in that order.
func TestPollTail_ReSeek(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Read the lines already in the file.
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

			// Shrink the file. The new lines are read from the start.
			<-time.After(200 * time.Millisecond)
			tailTest.TruncateFile("test.txt", "h311o\nw0r1d\nendofworld\n")

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

// After three shrinks, the collected lines include batch2_line1 from the first shrink and batch4_line1 from the last. The middle shrink is not checked.
func TestPollTail_MultipleTruncations(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start at the end, then shrink the file three times.
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

			// The first and last shrink show up.
			t.Logf("Lines read: %v", lines)
			assert.Contains(t, lines, "batch2_line1", "Should handle first truncation")
			assert.Contains(t, lines, "batch4_line1", "Should handle third truncation")
		})
	}
}

// =============================================================================
// Large Line Tests (adapted from TestOver4096ByteLine)
// =============================================================================

// A line of 4097 a's, longer than the default read buffer, arrives whole, between test and hello.
func TestPollTail_Over4096ByteLine(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// A line longer than the default read buffer is already in the file.
			tailTest := NewTailTest("over4096", t)
			testString := strings.Repeat("a", 4097)
			tailTest.CreateFile("test.txt", "test\n"+testString+"\nhello\nworld\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     nil,
			}

			tail := tailTest.StartTail("test.txt", config)
			// It arrives whole, with the lines around it.
			go tailTest.VerifyTailOutput(tail, []string{"test", testString, "hello", "world"}, false)

			<-time.After(200 * time.Millisecond)
			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

// A 128KB line arrives whole, then line2. The follow records no error.
func TestPollTail_LargeLines(t *testing.T) {
	// A 128KB line is already in the file.
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

	// It arrives whole, then the next line, and the follow records no error.
	forceReadForTest(fileTailer)
	_ = tail.Stop()
	<-done

	require.Len(t, lines, 2, "Should have read both lines")
	assert.Len(t, lines[0], len(largeLine), "First line should be 128KB")
	assert.Equal(t, "line2", lines[1], "Second line should be line2")
	assert.NoError(t, tail.Err(), "Should handle large lines without error")
}
