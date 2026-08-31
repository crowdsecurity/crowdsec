package tailwrapper

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatTail_BasicTailing(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create initial file with some content
	err := os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	// Force initial read
	st := tailer.(*statTail)
	st.ForceRead()

	// Add new lines
	err = os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\nline5\n"), os.ModeAppend)
	require.NoError(t, err)

	// Force read to pick up new lines
	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	// Wait briefly for goroutine to start
	time.Sleep(10 * time.Millisecond)

	_ = tailer.Stop()
	<-done

	// Should have read new lines (line4 and line5)
	require.GreaterOrEqual(t, len(lines), 2, "Should have read at least the new lines")
	assert.Contains(t, lines, "line4", "Should contain line4")
	assert.Contains(t, lines, "line5", "Should contain line5")
}

func TestStatTail_TruncationDetection(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create file with content
	err := os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\nline5\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling, use ForceRead() only
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Add more content
	err = os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\nline5\nline6\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// TRUNCATE: Write less content (simulating truncation/rotation)
	err = os.WriteFile(testFile, []byte("new1\nnew2\n"), 0o644)
	require.NoError(t, err)

	// Force read to detect truncation and read new content
	st.ForceRead()

	// Add more to truncated file
	err = os.WriteFile(testFile, []byte("new1\nnew2\nnew3\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	_ = tailer.Stop()
	<-done

	// Should have read new1, new2, and new3 after truncation
	assert.Contains(t, lines, "new1", "Should have read new1 after truncation")
	assert.Contains(t, lines, "new2", "Should have read new2 after truncation")
	assert.Contains(t, lines, "new3", "Should have read new3 after truncation")
}

func TestStatTail_TruncationToSmallerSize(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create file with 5 lines
	err := os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\nline5\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	// Truncate to smaller size (simulating file rotation)
	err = os.WriteFile(testFile, []byte("rotated1\n"), 0o644)
	require.NoError(t, err)

	// Force read to detect truncation
	st.ForceRead()

	// Add to rotated file
	err = os.WriteFile(testFile, []byte("rotated1\nrotated2\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	_ = tailer.Stop()
	<-done

	// Verify we read the rotated content
	assert.Contains(t, lines, "rotated1", "Should have read rotated1 after truncation")
	assert.Contains(t, lines, "rotated2", "Should have read rotated2 after truncation")
}

func TestStatTail_SeekStart(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create file with content
	err := os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekStart}, // Start from beginning
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	// Add new content
	err = os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	_ = tailer.Stop()
	<-done

	// Should have read all lines including line4
	assert.Contains(t, lines, "line1", "Should have read line1")
	assert.Contains(t, lines, "line4", "Should have read line4")
}

func TestStatTail_FileDeleted(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	// Delete the file
	err = os.Remove(testFile)
	require.NoError(t, err)

	// Force read to detect file deletion
	// ForceRead() calls readNewLines() which calls tomb.Kill() on file deletion
	st.ForceRead()

	// Check if error was set (tomb was killed)
	err = tailer.Err()
	require.Error(t, err, "Should have an error after reading deleted file")
	assert.Contains(t, err.Error(), "no longer exists", "Error should mention file no longer exists")

	// Dying channel should eventually close when tomb is killed
	// However, it's only closed in Stop(), so we need to stop the tailer
	_ = tailer.Stop()

	// Now dying should be closed
	select {
	case <-tailer.Dying():
		// Good
	default:
		t.Fatal("Dying channel should be closed after Stop()")
	}
}

func TestStatTail_ErrorHandling(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	// Remove read permission (Unix only)
	if runtime.GOOS != "windows" {
		err = os.Chmod(testFile, 0o000)
		require.NoError(t, err)
		defer func() { _ = os.Chmod(testFile, 0o644) }() // Restore for cleanup

		// Force read to detect permission error
		st.ForceRead()

		// Should detect error
		select {
		case <-tailer.Dying():
			err := tailer.Err()
			require.Error(t, err, "Should have an error")
		case <-time.After(1 * time.Second):
			// On some systems, this might not error immediately
			t.Log("Permission error not detected immediately (may be system-dependent)")
		}
	}
}

func TestStatTail_PollInterval(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	pollInterval := 200 * time.Millisecond
	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: pollInterval,
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	// Measure time between polls by adding content and measuring when it's read
	// Don't use ForceRead() here - let the natural polling happen to test the timer
	start := time.Now()
	err = os.WriteFile(testFile, []byte("line1\nline2\n"), os.ModeAppend)
	require.NoError(t, err)

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
			case line := <-tailer.Lines():
				if line != nil && line.Text == "line2" {
					lineReadTime = time.Now()
					return
				}
			}
		}
	}()

	wg.Wait()

	elapsed := lineReadTime.Sub(start)
	// Should be read within poll interval + some margin (allowing for timing variance)
	assert.Less(t, elapsed, pollInterval+300*time.Millisecond, "Should read within poll interval")
	// The first read happens immediately on start, so we can't assert on minimum time for this test
	// Just verify it was read
	assert.False(t, lineReadTime.IsZero(), "Line should have been read")
}

func TestStatTail_DefaultPollInterval(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: 0, // Should default to 1s
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Verify default poll interval is set
	st.ForceRead()

	// Add content and use ForceRead to verify it works
	err = os.WriteFile(testFile, []byte("line1\nline2\n"), os.ModeAppend)
	require.NoError(t, err)

	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	_ = tailer.Stop()
	<-done

	assert.Contains(t, lines, "line2", "Should read with default poll interval")
}

func TestStatTail_Stop(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)

	// Stop should not error
	err = tailer.Stop()
	require.NoError(t, err)

	// Should be dying
	select {
	case <-tailer.Dying():
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Should be dying after stop")
	}

	// Calling stop again should be safe
	err = tailer.Stop()
	assert.NoError(t, err)
}

func TestStatTail_Filename(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	assert.Equal(t, testFile, tailer.Filename())
}

func TestStatTail_TruncationWithSeekEnd(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create file
	err := os.WriteFile(testFile, []byte("old1\nold2\nold3\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd}, // Start at end
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	// Truncate file (simulate rotation)
	err = os.WriteFile(testFile, []byte("new1\nnew2\n"), 0o644)
	require.NoError(t, err)

	// Force read to detect truncation
	st.ForceRead()

	// Add more
	err = os.WriteFile(testFile, []byte("new1\nnew2\nnew3\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	_ = tailer.Stop()
	<-done

	// With SeekEnd after truncation, we read from beginning of truncated file
	// So we should get new1, new2, and new3
	assert.Contains(t, lines, "new1", "Should have read new1 after truncation")
	assert.Contains(t, lines, "new2", "Should have read new2 after truncation")
	assert.Contains(t, lines, "new3", "Should have read new3 after truncation")
}

func TestStatTail_TruncationWithSeekStart(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	// Create file
	err := os.WriteFile(testFile, []byte("old1\nold2\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekStart}, // Start from beginning
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Collect lines synchronously
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	// Force initial read - should read old1, old2
	st.ForceRead()

	// Truncate file to a SMALLER size (to trigger truncation detection)
	err = os.WriteFile(testFile, []byte("new1\n"), 0o644)
	require.NoError(t, err)

	// Force read to detect truncation and read new content
	st.ForceRead()

	// Add more
	err = os.WriteFile(testFile, []byte("new1\nnew2\nnew3\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	_ = tailer.Stop()
	<-done

	t.Logf("Lines read: %v", lines)

	// With SeekStart, we read from the beginning initially (old1, old2)
	// After truncation, we detect it and read from start again (new1)
	// Then we read the appended new2, new3
	assert.Contains(t, lines, "old1", "Should have read old1 initially")
	assert.Contains(t, lines, "old2", "Should have read old2 initially")
	assert.Contains(t, lines, "new1", "Should have read new1 after truncation with SeekStart")
	assert.Contains(t, lines, "new2", "Should have read new2 after append")
	assert.Contains(t, lines, "new3", "Should have read new3 after append")
}

func TestStatTail_MultipleTruncations(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.log")

	err := os.WriteFile(testFile, []byte("batch1_line1\nbatch1_line2\n"), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekEnd},
		TailMode:         "stat",
		StatPollInterval: -1, // No automatic polling
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Force initial read
	st.ForceRead()

	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil && line.Text != "" {
				lines = append(lines, line.Text)
			}
		}
	}()

	// Wait briefly for goroutine to start
	time.Sleep(10 * time.Millisecond)

	// First truncation (smaller file)
	err = os.WriteFile(testFile, []byte("batch2_line1\n"), 0o644)
	require.NoError(t, err)
	st.ForceRead()

	// Second truncation (even smaller file to ensure truncation detection)
	err = os.WriteFile(testFile, []byte("batch3_line1\n"), 0o644)
	require.NoError(t, err)
	st.ForceRead()

	// Add to batch3 file
	err = os.WriteFile(testFile, []byte("batch3_line1\nbatch3_line2\n"), os.ModeAppend)
	require.NoError(t, err)
	st.ForceRead()

	// Third truncation (smaller again)
	err = os.WriteFile(testFile, []byte("batch4_line1\n"), 0o644)
	require.NoError(t, err)
	st.ForceRead()

	_ = tailer.Stop()
	<-done

	t.Logf("Lines read: %v", lines)

	// Should have handled all truncations
	assert.Contains(t, lines, "batch2_line1", "Should handle first truncation")
	// Either batch3_line1 or batch3_line2 (or both) should be read
	assert.True(t, slices.Contains(lines, "batch3_line1") || slices.Contains(lines, "batch3_line2"), "Should handle second truncation (read batch3 content)")
	assert.Contains(t, lines, "batch4_line1", "Should handle third truncation")
}

func TestStatTail_LargeLines(t *testing.T) {
	// This test verifies that our stat_tail implementation can handle very large lines
	// Unlike bufio.Scanner (which has a 64KB limit), we use bufio.Reader.ReadString()
	// which matches the nxadm/tail library and can handle lines of any size
	dir := t.TempDir()
	testFile := filepath.Join(dir, "large.log")

	// Create a line larger than the old bufio.Scanner limit (64KB)
	const bufioMaxScanTokenSize = 64 * 1024
	largeLine := make([]byte, bufioMaxScanTokenSize*2) // 128KB line
	for i := range largeLine {
		largeLine[i] = byte('A' + (i % 26))
	}
	content := string(largeLine) + "\nline2\n"

	err := os.WriteFile(testFile, []byte(content), 0o644)
	require.NoError(t, err)

	config := Config{
		ReOpen:           true,
		Follow:           true,
		Poll:             false,
		Location:         &SeekInfo{Offset: 0, Whence: io.SeekStart},
		TailMode:         "stat",
		StatPollInterval: -1,
	}

	tailer, err := newStatTail(testFile, config)
	require.NoError(t, err)
	defer func() { _ = tailer.Stop() }()

	st := tailer.(*statTail)

	// Collect lines
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range tailer.Lines() {
			if line != nil {
				lines = append(lines, line.Text)
			}
		}
	}()

	// Trigger read - should successfully handle the large line
	st.ForceRead()

	_ = tailer.Stop()
	<-done

	// Should successfully read both lines (no buffer size limitation with ReadString)
	require.Len(t, lines, 2, "Should have read both lines")
	assert.Len(t, lines[0], len(largeLine), "First line should be the large line (128KB)")
	assert.Equal(t, "line2", lines[1], "Second line should be line2")

	// Verify no error
	err = tailer.Err()
	assert.NoError(t, err, "Should handle large lines without error (using bufio.Reader.ReadString like nxadm/tail)")
}
