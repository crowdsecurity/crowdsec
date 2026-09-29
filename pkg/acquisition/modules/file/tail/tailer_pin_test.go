// Copyright (c) 2024 CrowdSec
//
// These tests provide little value for review. They pin a local result: a stored path, a predicate
// table, or an assertion that still passes when the behavior under test does not happen.
// They stay so that an AI agent changing this package has to look twice at unintended drift when one of them breaks.
// The file ends in _test.go so Go compiles it with the tests. Tests that fail when the behavior is wrong stay in tailer_test.go.

package tail

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cancels the tail. If it does not stop within half a second, the test stops it anyway, so a missed cancel still passes.
func TestTailer_ContextCancellation(t *testing.T) {
	for _, mode := range tailerModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			testFile := filepath.Join(dir, "test.log")

			err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(t.Context())

			config := Config{
				PollInterval: 50 * time.Millisecond,
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

// Removing the file makes the next read report that it is gone. The follow-ended check runs only after Stop, so this does not prove the deletion itself ended the follow.
func TestTailer_FileDeleted(t *testing.T) {
	// Test closeAfterRead mode for file deletion
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

// Drops read permission and hopes the next read notices. If it does not notice within a second, the test logs that and still passes.
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
		Location:     &SeekInfo{Offset: 0, Whence: io.SeekEnd},
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

func TestOffsetAfterLastNewlineMissingFile(t *testing.T) {
	_, err := offsetAfterLastNewline(filepath.Join(t.TempDir(), "missing.log"), 10)
	require.Error(t, err)
	require.ErrorContains(t, err, "could not open file")
}

// An empty file starts at byte 0. The file is not opened to discover that.
func TestOffsetAfterLastNewlineEmptyFile(t *testing.T) {
	offset, err := offsetAfterLastNewline("unused", 0)
	require.NoError(t, err)
	require.Equal(t, int64(0), offset)
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

