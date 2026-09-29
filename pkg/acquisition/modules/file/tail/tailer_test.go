// Copyright (c) 2024 CrowdSec
//
// Tests in this file fail when the behavior is wrong.
// The one-to-one upstream suite lives in tailer_admx_test.go.
// Tests that still pass when the behavior is missing live in tailer_pin_test.go.

package tail

import (
	"bufio"
	"context"
	"errors"
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

// Lines already in the file are skipped. Only lines appended after the tail starts are delivered.
func TestTailer_BasicTailing(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("basic", t)

			tailTest.CreateFile("test.txt", "line1\nline2\nline3\n")

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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
		PollInterval: pollInterval,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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

func TestTailer_SeekStart(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\nline2\n"), 0o644)
			require.NoError(t, err)

			config := Config{
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
				PollInterval: 50 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
					PollInterval: -1,
					Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
				PollInterval: 20 * time.Millisecond,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		PollInterval: -1, // Manual mode
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		PollInterval: 20 * time.Millisecond,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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

// A transient stat error ends the tail on purpose. This tailer does not retry.
// The file is still readable after the error, and a line written then is not delivered.
// Starting again is the file source's job, when discovery polling notices the path is not being followed.
func TestTailer_TransientStatFailureClosesDying(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

	transientStatError := errors.New("transient network error")
	statFailedOnce := false
	originalStat := statFileInTest
	t.Cleanup(func() { statFileInTest = originalStat })
	statFileInTest = func(name string) (os.FileInfo, error) {
		if !statFailedOnce {
			statFailedOnce = true
			return nil, transientStatError
		}
		return os.Stat(name)
	}

	followed, err := TailFile(t.Context(), testFile, Config{
		PollInterval: 20 * time.Millisecond,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = followed.Stop() })

	select {
	case <-followed.Dying():
	case <-time.After(2 * time.Second):
		t.Fatal("Dying stayed open after a transient stat error")
	}

	require.ErrorIs(t, followed.Err(), transientStatError)
	_, err = os.Stat(testFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(testFile, []byte("old\nafter\n"), 0o644))

	select {
	case line, ok := <-followed.Lines():
		if ok {
			t.Fatalf("tail delivered %q after a transient stat error", line.Text)
		}
	default:
		t.Fatal("Lines stayed open after the tail died")
	}
}

func TestTailer_RecordFirstErrorAndStopClosesDying(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })
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

func TestTailer_StatOpenFailureStopsFollow(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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

func TestTailer_PermissionStatTreatedAsGone(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
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
