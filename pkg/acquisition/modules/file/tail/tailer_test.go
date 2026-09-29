// Tests in this file fail when the behavior is wrong.
// The one-to-one upstream suite lives in tailer_admx_test.go.

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

// SeekStart delivers a line already in the file, then a line appended after that read.
func TestTailer_SeekStart(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("seek-start", t)
			tailTest.CreateFile("test.txt", "line1\nline2\nline3\n")

			config := Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
			}

			tail := tailTest.StartTail("test.txt", config)

			go tailTest.VerifyTailOutput(tail, []string{"line1", "line2", "line3", "line4"}, false)

			forceReadForTest(tail)
			tailTest.AppendFile("test.txt", "line4\n")
			forceReadForTest(tail)

			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

// Renaming the file leaves it behind. A line written there after the last check is not delivered.
// The new file at the same path is read from the start.
func TestTailer_FileRotation(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			tailTest := NewTailTest("rotation", t)
			tailTest.CreateFile("test.txt", "kept\n")

			tail := tailTest.StartTail("test.txt", Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			})
			defer func() { require.NoError(t, tail.Stop()) }()

			forceReadForTest(tail)
			tailTest.RenameFile("test.txt", "test.txt.1")
			tailTest.AppendFile("test.txt.1", "lost\n")
			tailTest.CreateFile("test.txt", "fresh\n")
			forceReadForTest(tail)

			var got []string
		drain:
			for {
				select {
				case line := <-tail.Lines():
					require.NotNil(t, line)
					got = append(got, line.Text)
				default:
					break drain
				}
			}
			require.NotContains(t, got, "lost")
			require.Equal(t, []string{"fresh"}, got)
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

// A fragment already in the file is left behind. The next line is only what is appended after the end.
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
			assert.Equal(t, `1}`, readTailLineForTest(t, tail))
			assertNoTailLineForTest(t, tail)
		})
	}
}

// A line appended during a read is delivered once, not again on the next read.
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

// Deleting the file ends the follow on its own. The test does not call Stop first.
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

// A stat error on the open handle, after the line was read, ends the tail.
// The line already sent stays sent. A line written after that is not delivered.
// Starting again is the file source's job, the same as any other transient failure.
func TestTailer_StatAfterReadFailureClosesDying(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

	statAfterReadError := errors.New("stat after read failed")
	originalStat := statOpenedFileInTest
	t.Cleanup(func() { statOpenedFileInTest = originalStat })
	statOpenedFileInTest = func(*os.File) (os.FileInfo, error) {
		return nil, statAfterReadError
	}

	fileTailer, err := TailFile(t.Context(), testFile, Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fileTailer.Stop() })

	forceReadForTest(fileTailer)

	select {
	case <-fileTailer.Dying():
	case <-time.After(2 * time.Second):
		t.Fatal("Dying stayed open after a stat error on the open handle")
	}

	require.Equal(t, "old", readTailLineForTest(t, fileTailer))
	require.ErrorIs(t, fileTailer.Err(), statAfterReadError)
	require.NoError(t, appendToFileInTest(testFile, "after\n"))

	select {
	case line, ok := <-fileTailer.Lines():
		if ok {
			t.Fatalf("tail delivered %q after a stat error on the open handle", line.Text)
		}
	default:
		t.Fatal("Lines stayed open after the tail died")
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

// A handle that cannot be positioned stops the follow.
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

// A read error on the opened handle stops the follow.
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

// The tailer reports the path it was started on.
func TestTailer_Filename(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		PollInterval: -1,
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, tail.Stop()) }()

	assert.Equal(t, testFile, tail.Filename())
}

// Removing the file makes the next read report an error and close Dying.
func TestTailer_FileDeleted(t *testing.T) {
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
	defer func() { _ = tail.Stop() }()

	forceReadForTest(tail)

	err = os.Remove(testFile)
	require.NoError(t, err)

	forceReadForTest(tail)

	err = tail.Err()
	require.Error(t, err, "Should have an error after file deletion")
	assert.Contains(t, err.Error(), "no longer exists")

	select {
	case <-tail.Dying():
	case <-time.After(time.Second):
		t.Fatal("Dying stayed open after the file was deleted")
	}
}

// Dropping read permission makes the next read report an error and close Dying.
func TestTailer_ErrorHandling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Permission tests not reliable on Windows")
	}

	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		PollInterval: -1,
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
	}

	tail, err := TailFile(t.Context(), testFile, config)
	require.NoError(t, err)
	defer func() { _ = tail.Stop() }()

	err = os.Chmod(testFile, 0o000)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(testFile, 0o644) }()

	forceReadForTest(tail)

	err = tail.Err()
	require.Error(t, err, "Should have an error after read permission was removed")
	assert.Contains(t, err.Error(), "error opening file")

	select {
	case <-tail.Dying():
	case <-time.After(1 * time.Second):
		t.Fatal("Dying stayed open after read permission was removed")
	}
}

// A missing path counts as gone. On Windows a permission error does too, because deleting a locked file is reported that way. Elsewhere a permission error is a real error.
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
