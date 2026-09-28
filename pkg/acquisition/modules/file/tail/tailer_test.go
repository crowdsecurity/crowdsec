// Copyright (c) 2024 CrowdSec
//
// Tests in this file are ours. The one-to-one upstream suite lives in tailer_admx_test.go.

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

	fileTailer := tail
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

	fileTailer := tail
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

			fileTailer := tail
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

	fileTailer := tail
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

	fileTailer := followed
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
	return followed
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

// A keep-open start fails when the opened handle cannot be seeked.
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

// A keep-open start fails when the path cannot be watched after it is unlinked.
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

// A create watch event reads the new complete line the same way a write does.
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

// Stop while waitUntilFileReturns is blocked ends the wait.
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

// A keep-open read records an error when the handle can no longer be statted.
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

// A keep-open reopen records an error when the replacement handle cannot be seeked.
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

// A close-after-read pass records an error when the file cannot be opened.
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

// A close-after-read pass records an error when the reopened handle cannot be seeked.
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

// A canceled follow does not send a line that was read after cancel.
func TestTailer_EnqueueLineDropsWhenFollowCanceled(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	fileTailer := &tailer{
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

// sendCompleteLines returns a read error when a fragment is not at EOF.
func TestTailer_SendCompleteLinesReturnsReadErrorOnPartialChunk(t *testing.T) {
	fileTailer := &tailer{lines: make(chan *Line, 1), done: make(chan struct{})}
	_, _, err := fileTailer.sendCompleteLines(bufio.NewReader(&failAfterBytesReaderForTest{
		data: []byte("partial"),
		err:  os.ErrPermission,
	}))
	require.ErrorIs(t, err, os.ErrPermission)
}

// sendCompleteLines returns a read error after a complete line when the next read fails.
func TestTailer_SendCompleteLinesReturnsReadErrorAfterLine(t *testing.T) {
	fileTailer := &tailer{lines: make(chan *Line, 1), done: make(chan struct{})}
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

func TestOffsetAfterLastNewlineMissingFile(t *testing.T) {
	_, err := offsetAfterLastNewline(filepath.Join(t.TempDir(), "missing.log"), 10)
	require.Error(t, err)
	require.ErrorContains(t, err, "could not open file")
}

func TestOffsetAfterLastNewlineNoNewline(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("nonewline"), 0o644))

	offset, err := offsetAfterLastNewline(testFile, 9)
	require.NoError(t, err)
	require.Equal(t, int64(0), offset)
}

func TestOffsetAfterLastNewlineEmptyFile(t *testing.T) {
	offset, err := offsetAfterLastNewline("unused", 0)
	require.NoError(t, err)
	require.Equal(t, int64(0), offset)
}

// SeekEnd fails when the file cannot be opened again to find the last newline.
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

// A close-after-read pass records a stat error that is not a missing file.
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

// A close-after-read pass records an error when the opened handle cannot be read.
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

// A keep-open read records an error when the buffered reader fails.
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

// A Remove delivered on the follow loop's watch channel ends the tail when ReOpen is off.
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

// A remove-and-recreate with a watcher installed watches the new path.
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

func TestFilePathGone(t *testing.T) {
	require.False(t, filePathGone(nil))
	require.True(t, filePathGone(os.ErrNotExist))
	require.False(t, filePathGone(os.ErrClosed))

	if runtime.GOOS == "windows" {
		require.True(t, filePathGone(os.ErrPermission))
		return
	}
	require.False(t, filePathGone(os.ErrPermission))
}

func TestWatchEventMeansContentChanged(t *testing.T) {
	require.True(t, watchEventMeansContentChanged(fsnotify.Write))
	require.True(t, watchEventMeansContentChanged(fsnotify.Create))
	require.True(t, watchEventMeansContentChanged(fsnotify.Chmod))
	require.False(t, watchEventMeansContentChanged(fsnotify.Remove))
	require.False(t, watchEventMeansContentChanged(0))
}

// A chmod watch event reads the new complete line. Linux inotify reports chmod when an open file is unlinked; a real chmod is also a content check.
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

// A chmod watch event when the path is gone ends the follow the same way a remove does.
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

// Windows share-delete lets a rotator remove the file while the keep-open handle is still held.
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

// A Stat permission error is a gone path on Windows and a follow error elsewhere.
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
