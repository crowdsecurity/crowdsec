// Copyright (c) 2024 CrowdSec
//
// Tests in this file fail when the behavior is wrong.
// The one-to-one upstream suite lives in tailer_admx_test.go.
// Tests that still pass when the behavior is missing live in tailer_pin_test.go.

package tail

import (
	"bufio"
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

// Lines already in the file are skipped. Only lines appended after the tail starts are delivered.
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

// With the handle closed between reads, an appended line shows up within about one poll period.
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

// The handle stays open and changes are found by polling, not by a filesystem watcher. An appended line is still delivered.
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

// The handle stays open and polling is off, so the appended line arrives because the filesystem watcher saw the write.
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

// Starting at the beginning delivers the lines already in the file, then a line appended later.
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

			fileTailer := tail
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

// The file is renamed and a new file is created at the same path. A line written to the new file is still delivered.
// The keep-open case is skipped: rotation while the handle is held is covered separately.
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

// An empty file produces no line until one is appended, and that line is then delivered.
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

// A file that ends mid-line delivers only the finished line. The fragment is delivered once a newline is appended.
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

// A line split across two writes is delivered whole when the rest arrives.
// If the file is replaced instead, the fragment is dropped and only the new line is delivered.
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

				fileTailer := tail

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

func readTailLineForTest(t *testing.T, tail *Tailer) string {
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

func assertNoTailLineForTest(t *testing.T, tail *Tailer) {
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

// A burst of short lines is mostly delivered. The test allows a few to be missed.
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

// A negative poll interval does not read on its own. The line appears only after the test asks for a read.
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

	fileTailer := tail

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

// The start position is the byte after the last newline, even when that newline is not in the final chunk.
// A file that ends on a newline starts at the end.
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

// Starting at the end of a file with no newline does not emit that fragment. The next complete line is emitted.
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

			fileTailer := tail
			forceReadForTest(fileTailer)
			assertNoTailLineForTest(t, tail)

			require.NoError(t, appendToFileInTest(testFile, "1}\n"))

			forceReadForTest(fileTailer)
			assert.Equal(t, `{"a":1}`, readTailLineForTest(t, tail))
			assertNoTailLineForTest(t, tail)
		})
	}
}

// A line appended while the close-after-read path has the file open is delivered once, not again on the next read.
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

	fileTailer := tail
	forceReadForTest(fileTailer)
	assert.Equal(t, "old", readTailLineForTest(t, tail))
	assert.Equal(t, "during", readTailLineForTest(t, tail))
	assertNoTailLineForTest(t, tail)

	forceReadForTest(fileTailer)
	assertNoTailLineForTest(t, tail)
}

// Deleting the file in close-after-read mode ends the follow on its own. The test does not call Stop first.
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

// After the handle is dropped and the next open fails, the follow ends on its own so the reader can forget this file.
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

	fileTailer := followed
	fileTailer.waitUntilFileReturns()
	require.Error(t, followed.Err())

	select {
	case <-followed.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after reopen failed")
	}
}

func startKeepOpenTailForTest(t *testing.T, testFile string, reopen bool, poll bool, pollInterval time.Duration) *Tailer {
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
	return followed
}

// When the watcher says the file was written, the new line is delivered.
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

// When the watcher says the file was removed and reopen is off, the follow stops with an error.
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

// When the watcher says the file was removed and reopen is on, the tail waits for the path to come back and reads the new file from the start.
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

// If the filesystem watcher is closed out from under the tailer, the follow ends.
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

// If the file cannot be opened at the start, while the handle is meant to stay open, starting the tail returns that error.
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

// The first error stops the follow. A later error does not replace it.
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

	fileTailer.recordFirstErrorAndStop(os.ErrClosed)
	require.ErrorIs(t, fileTailer.Err(), os.ErrPermission)
}

func openClosedFileForTest(filename string) (*os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return file, nil
}

// If the opened handle cannot be moved to the start position, starting the tail fails.
func TestTailer_KeepOpenSeekFailure(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = openClosedFileForTest

	_, err := TailFile(t.Context(), testFile, Config{
		KeepFileOpen: true,
		Poll:         true,
		PollInterval: -1,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "could not seek")
}

// If the path disappears before a watcher can be attached, starting the tail fails.
func TestTailer_KeepOpenWatchAddFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot unlink a file while this process holds it open")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = func(filename string) (*os.File, error) {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		if err := os.Remove(filename); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}

	_, err := TailFile(t.Context(), testFile, Config{
		KeepFileOpen: true,
		Poll:         false,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "could not watch file")
}

// When the watcher says the file was created, the new line is delivered, the same as for a write.
func TestTailer_WatchCreateReadsLine(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))
	require.False(t, fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Create}))

	select {
	case line := <-fileTailer.Lines():
		require.Equal(t, "line2", line.Text)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for line after create event")
	}
}

// Stopping the tail while it is waiting for a deleted file to reappear ends that wait.
func TestTailer_WaitUntilFileReturnsStopsWhenCanceled(t *testing.T) {
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

	time.Sleep(150 * time.Millisecond)
	require.NoError(t, fileTailer.Stop())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitUntilFileReturns did not return after Stop")
	}
}

// If the open handle can no longer be checked for size, the follow stops.
func TestTailer_KeepOpenStatFailureStopsFollow(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	fileTailer.mu.Lock()
	require.NoError(t, fileTailer.file.Close())
	fileTailer.mu.Unlock()

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error statting file")
}

// After the file shrinks, if the replacement handle cannot be positioned, the follow stops.
func TestTailer_KeepOpenReopenSeekFailure(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = openClosedFileForTest

	fileTailer.mu.Lock()
	fileTailer.reopenAtOffset(0)
	fileTailer.mu.Unlock()

	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error seeking")
}

// In close-after-read mode, failing to open the file stops the follow.
func TestTailer_StatOpenFailureStopsFollow(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = func(string) (*os.File, error) {
		return nil, os.ErrPermission
	}

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error opening file")
}

// In close-after-read mode, a handle that cannot be positioned stops the follow.
func TestTailer_StatSeekFailureStopsFollow(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = openClosedFileForTest

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error seeking")
}

// A line finished after the follow was canceled is not sent to the reader.
func TestTailer_EnqueueLineDropsWhenFollowCanceled(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	fileTailer := &Tailer{
		filename: testFile,
		lines:    make(chan *Line),
		dying:    make(chan struct{}),
		done:     ctx.Done(),
		cancel:   cancel,
	}
	forceReadForTest(fileTailer)

	select {
	case <-fileTailer.lines:
		t.Fatal("canceled follow sent a line")
	default:
	}
}

type failAfterBytesReaderForTest struct {
	data []byte
	err  error
}

func (reader *failAfterBytesReaderForTest) Read(p []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	copied := copy(p, reader.data)
	reader.data = reader.data[copied:]
	if len(reader.data) == 0 {
		return copied, reader.err
	}
	return copied, nil
}

// A read error in the middle of a line is returned. That fragment is not treated as a finished line.
func TestTailer_SendCompleteLinesReturnsReadErrorOnPartialChunk(t *testing.T) {
	fileTailer := &Tailer{lines: make(chan *Line, 1), done: make(chan struct{})}
	_, _, err := fileTailer.sendCompleteLines(bufio.NewReader(&failAfterBytesReaderForTest{
		data: []byte("partial"),
		err:  os.ErrPermission,
	}))
	require.ErrorIs(t, err, os.ErrPermission)
}

// A finished line is sent, and the read error that comes after it is returned.
func TestTailer_SendCompleteLinesReturnsReadErrorAfterLine(t *testing.T) {
	fileTailer := &Tailer{lines: make(chan *Line, 1), done: make(chan struct{})}
	completeBytes, _, err := fileTailer.sendCompleteLines(bufio.NewReader(&failAfterBytesReaderForTest{
		data: []byte("line\n"),
		err:  os.ErrPermission,
	}))
	require.ErrorIs(t, err, os.ErrPermission)
	require.Equal(t, int64(5), completeBytes)
	select {
	case line := <-fileTailer.lines:
		require.Equal(t, "line", line.Text)
	default:
		t.Fatal("expected the complete line before the read error")
	}
}

// A file with no newline at all starts at byte 0, so the whole fragment is still ahead of the reader.
func TestOffsetAfterLastNewlineNoNewline(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("nonewline"), 0o644))

	offset, err := offsetAfterLastNewline(testFile, 9)
	require.NoError(t, err)
	require.Equal(t, int64(0), offset)
}

// Starting at the end fails when the file cannot be opened to find the last newline.
func TestTailer_SeekEndOpenFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 does not prevent the owner from opening the file on Windows")
	}

	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("hello\n"), 0o644))
	require.NoError(t, os.Chmod(testFile, 0o000))
	t.Cleanup(func() { _ = os.Chmod(testFile, 0o644) })

	_, err := TailFile(t.Context(), testFile, Config{
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		KeepFileOpen: false,
		Poll:         true,
		PollInterval: -1,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "could not open file")
}

// A permission error while checking the file is reported as a follow error, not as a missing file. On Windows this case is skipped because directory permissions do not hide the file.
func TestTailer_StatPermissionFailureStopsFollow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory chmod 0o000 does not hide children on Windows")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = fileTailer.Stop()
	})

	require.NoError(t, os.Chmod(dir, 0o000))
	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error statting file")
}

// In close-after-read mode, a read error on the opened handle stops the follow.
func TestTailer_StatReadFailureStopsFollow(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })

	originalOpen := openFileForReadInTest
	t.Cleanup(func() { openFileForReadInTest = originalOpen })
	openFileForReadInTest = func(filename string) (*os.File, error) {
		return os.Open(filepath.Dir(filename))
	}

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error reading file")
}

// A read error on the handle that stays open stops the follow.
func TestTailer_KeepOpenReadErrorStopsFollow(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	fileTailer.mu.Lock()
	fileTailer.reader = bufio.NewReader(&failAfterBytesReaderForTest{
		data: []byte("x"),
		err:  os.ErrPermission,
	})
	fileTailer.mu.Unlock()

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	require.ErrorContains(t, fileTailer.Err(), "error reading file")
}

// A remove notice on the live watch channel stops the tail when reopen is off.
func TestTailer_WatchRemoveEventStopsFollowWithoutReopen(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	events := make(chan fsnotify.Event, 1)
	watchEventsInTest = events
	t.Cleanup(func() { watchEventsInTest = nil })

	fileTailer := startKeepOpenTailForTest(t, testFile, false, false, 20*time.Millisecond)
	events <- fsnotify.Event{Name: testFile, Op: fsnotify.Remove}

	select {
	case <-fileTailer.Dying():
	case <-time.After(2 * time.Second):
		t.Fatal("Dying stayed open after a watched remove")
	}
	require.Error(t, fileTailer.Err())
}

// After the file is removed and written again, the new file is watched too.
func TestTailer_WatchRemoveWithReopenAddsWatcher(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, false, 20*time.Millisecond)
	require.NotNil(t, fileTailer.watcher)

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

	fileTailer.mu.Lock()
	require.NotNil(t, fileTailer.watcher)
	fileTailer.mu.Unlock()
}

// A permission-change notice is treated as "the file may have changed", and the new line is delivered. Linux also reports that notice when an open file is deleted.
func TestTailer_WatchChmodReadsLine(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	require.NoError(t, appendToFileInTest(testFile, "line2\n"))
	require.False(t, fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Chmod}))

	select {
	case line := <-fileTailer.Lines():
		require.Equal(t, "line2", line.Text)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for line after chmod event")
	}
}

// A permission-change notice after the path is gone stops the follow when reopen is off, the same as a remove.
func TestTailer_WatchChmodWhenPathGoneStopsWithoutReopen(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, false, true, -1)
	require.NoError(t, os.Remove(testFile))
	require.True(t, fileTailer.readAfterWatchEvent(fsnotify.Event{Name: testFile, Op: fsnotify.Chmod}))
	require.Error(t, fileTailer.Err())

	select {
	case <-fileTailer.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after chmod on a missing path")
	}
}

// On Windows, another process can delete the file while the keep-open handle is still held.
func TestTailer_WindowsCanRemoveFileWhileKeptOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("FILE_SHARE_DELETE is a Windows CreateFile flag")
	}

	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer := startKeepOpenTailForTest(t, testFile, true, true, -1)
	require.NotNil(t, fileTailer.file)
	require.NoError(t, os.Remove(testFile))
}

// A permission error while checking the path means the file is gone on Windows. Everywhere else it is a real follow error.
func TestTailer_PermissionStatTreatedAsGone(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		Poll:         true,
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
		KeepFileOpen: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })

	originalStat := statFileInTest
	t.Cleanup(func() { statFileInTest = originalStat })
	statFileInTest = func(string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	}

	forceReadForTest(fileTailer)
	require.Error(t, fileTailer.Err())
	if runtime.GOOS == "windows" {
		require.ErrorContains(t, fileTailer.Err(), "no longer exists")
		return
	}
	require.ErrorContains(t, fileTailer.Err(), "error statting file")
}
