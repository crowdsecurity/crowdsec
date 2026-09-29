// The one-to-one upstream suite lives in tailer_admx_test.go.

package polltail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SeekStart delivers a line already in the file, then a line appended after that read.
func TestPollTail_SeekStart(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start at the beginning of a file that already has lines.
			tailTest := NewTailTest("seek-start", t)
			tailTest.CreateFile("test.txt", "line1\nline2\nline3\n")

			config := Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
			}

			tail := tailTest.StartTail("test.txt", config)

			go tailTest.VerifyTailOutput(tail, []string{"line1", "line2", "line3", "line4"}, false)

			// Read those lines, append one more, and read again.
			forceReadForTest(tail)
			tailTest.AppendFile("test.txt", "line4\n")
			forceReadForTest(tail)

			tailTest.waitForLineCheckThenStop(tail, true)
		})
	}
}

// Renaming the file leaves it behind. A line written there after the last check is not delivered.
// The new file at the same path is read from the start.
func TestPollTail_FileRotation(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start at the end.
			tailTest := NewTailTest("rotation", t)
			tailTest.CreateFile("test.txt", "kept\n")

			tail := tailTest.StartTail("test.txt", Config{
				PollInterval: -1,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
			})
			defer func() { require.NoError(t, tail.Stop()) }()

			forceReadForTest(tail)
			// Rename the file and write to both the old name and the new path.
			tailTest.RenameFile("test.txt", "test.txt.1")
			tailTest.AppendFile("test.txt.1", "lost\n")
			tailTest.CreateFile("test.txt", "fresh\n")
			forceReadForTest(tail)

			// The line left on the renamed file is absent. The new file's line arrives.
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

// Lines written in bursts for one second all arrive, in order.
// The poll is much shorter than that window, so several polls run while the writes happen.
func TestPollTail_RapidWrites(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Follow with a short poll.
			dir := t.TempDir()
			testFile := filepath.Join(dir, "rapid.log")
			require.NoError(t, os.WriteFile(testFile, nil, 0o644))

			const pollInterval = 100 * time.Millisecond
			tail, err := TailFile(t.Context(), testFile, Config{
				PollInterval: pollInterval,
				Location:     &SeekInfo{Offset: 0, Whence: io.SeekStart},
			})
			require.NoError(t, err)
			defer func() { require.NoError(t, tail.Stop()) }()

			// Write bursts for one second, across several polls.
			var written []string
			lineNumber := 0
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				var burst strings.Builder
				for range 5 {
					line := strconv.Itoa(lineNumber)
					lineNumber++
					written = append(written, line)
					burst.WriteString(line)
					burst.WriteByte('\n')
				}
				require.NoError(t, appendToFileInTest(testFile, burst.String()))
				time.Sleep(pollInterval / 2)
			}

			// Every written line arrives, in order.
			got := make([]string, 0, len(written))
			timeout := time.After(5 * time.Second)
			for len(got) < len(written) {
				select {
				case line := <-tail.Lines():
					require.NotNil(t, line)
					require.NoError(t, line.Err)
					got = append(got, line.Text)
				case <-timeout:
					t.Fatalf("got %d of %d lines", len(got), len(written))
				}
			}
			require.Equal(t, written, got)
			assertNoTailLineForTest(t, tail)
		})
	}
}

// A negative poll interval does not read on its own. The line appears only after the test asks for a read.
func TestPollTail_ManualModeReadsOnlyWhenAsked(t *testing.T) {
	// Start in manual mode on a file that already has a line.
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

	// Nothing is read until the test asks.
	select {
	case <-tail.Lines():
		t.Fatal("manual mode should not read before the test asks")
	case <-time.After(50 * time.Millisecond):
		// Expected
	}

	// One read delivers that line.
	forceReadForTest(fileTailer)

	var line *Line
	select {
	case line = <-tail.Lines():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("manual mode should read the line when the test asks")
	}
	assert.Equal(t, "initial", line.Text)
}

// A fragment already in the file is left behind. The next line is only what is appended after the end.
func TestPollTail_StartAtEndOfPartialLine(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			// Start at the end of a file that has no newline.
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

			// Append the rest of the line. Only that remainder arrives.
			require.NoError(t, appendToFileInTest(testFile, "1}\n"))

			forceReadForTest(fileTailer)
			assert.Equal(t, `1}`, readTailLineForTest(t, tail))
			assertNoTailLineForTest(t, tail)
		})
	}
}

// A line appended during a read is delivered once, not again on the next read.
func TestPollTail_StatReadDoesNotRepeatAppend(t *testing.T) {
	// The first open appends a line before the read sees the file.
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

	// That appended line arrives once.
	fileTailer := tail
	forceReadForTest(fileTailer)
	assert.Equal(t, "old", readTailLineForTest(t, tail))
	assert.Equal(t, "during", readTailLineForTest(t, tail))
	assertNoTailLineForTest(t, tail)

	// The next read delivers nothing.
	forceReadForTest(fileTailer)
	assertNoTailLineForTest(t, tail)
}

// A stat error on the open handle, after the line was read, ends the tail.
// The line already sent stays sent. A line written after that is not delivered.
// Starting again is the file source's job, the same as any other transient failure.
func TestPollTail_StatAfterReadFailureClosesDying(t *testing.T) {
	// The stat of the open handle fails after the line is read.
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

	// The follow ends. The line stays sent, and a later line is not delivered.
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
func TestPollTail_TransientStatFailureClosesDying(t *testing.T) {
	// The first stat fails. Later stats would succeed.
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

	// The follow ends and does not deliver a line written after that.
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

// The first recorded error ends the follow and closes Dying. A later error does not replace it.
func TestPollTail_RecordFirstErrorAndStopClosesDying(t *testing.T) {
	// The first recorded error ends the follow.
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

	// A second error does not replace it.
	fileTailer.recordFirstErrorAndStop(os.ErrClosed)
	require.ErrorIs(t, fileTailer.Err(), os.ErrPermission)
}

// A handle that cannot be positioned stops the follow.
func TestPollTail_StatSeekFailureStopsFollow(t *testing.T) {
	// The opened handle cannot be seeked. The follow records that error.
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
func TestPollTail_EnqueueLineDropsWhenFollowCanceled(t *testing.T) {
	// The follow is already canceled. A read does not send the line.
	testFile := filepath.Join(t.TempDir(), "test.log")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\n"), 0o644))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	fileTailer := &PollTail{
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

// A read error in the middle of a line is returned. That fragment is not treated as a finished line.
func TestPollTail_SendCompleteLinesReturnsReadErrorOnPartialChunk(t *testing.T) {
	// The read fails before a newline. That error is returned.
	fileTailer := &PollTail{lines: make(chan *Line, 1), done: make(chan struct{})}
	_, _, err := fileTailer.sendCompleteLines(bufio.NewReader(&failAfterBytesReaderForTest{
		data: []byte("partial"),
		err:  os.ErrPermission,
	}))
	require.ErrorIs(t, err, os.ErrPermission)
}

// A finished line is sent, and the read error that comes after it is returned.
func TestPollTail_SendCompleteLinesReturnsReadErrorAfterLine(t *testing.T) {
	// A complete line is followed by a read error. The line is sent, and the error is returned.
	fileTailer := &PollTail{lines: make(chan *Line, 1), done: make(chan struct{})}
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

// A read error on the opened handle stops the follow.
func TestPollTail_StatReadFailureStopsFollow(t *testing.T) {
	// The opened handle is a directory, so the read fails. The follow records that error.
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

// A permission error from stat stops the follow. On Windows that is reported as the file being gone.
func TestPollTail_PermissionStatTreatedAsGone(t *testing.T) {
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
func TestPollTail_Filename(t *testing.T) {
	// The reported path is the path TailFile was given.
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
func TestPollTail_FileDeleted(t *testing.T) {
	// Read once, then remove the file and read again.
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

	// The follow reports that the file is gone, and Dying closes.
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
func TestPollTail_ErrorHandling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Permission tests not reliable on Windows")
	}

	// Remove read permission and read again.
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

	// The follow reports an open error, and Dying closes.
	err = tail.Err()
	require.Error(t, err, "Should have an error after read permission was removed")
	assert.Contains(t, err.Error(), "error opening file")

	select {
	case <-tail.Dying():
	case <-time.After(1 * time.Second):
		t.Fatal("Dying stayed open after read permission was removed")
	}
}
