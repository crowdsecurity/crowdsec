// This test suite exercises the live tail modes and checks that they behave the same (simmetry)
// tail uses nxadm. polltail uses the in-house tailer.
package fileacquisition_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// liveTailMode is one live file mode. tail uses nxadm. polltail uses the in-house tailer.
type liveTailMode struct {
	name  string
	mode  string
	extra string
}

// tailModes covers each live file mode.
var tailModes = []liveTailMode{
	{name: "tail", mode: "tail"},
	{name: "polltail", mode: "polltail", extra: "\npolltail_read_interval: 100ms"},
}

// forEachLiveTailMode runs test once per live tail mode, as a subtest named for that mode.
func forEachLiveTailMode(t *testing.T, test func(t *testing.T, mode liveTailMode)) {
	t.Helper()
	for _, mode := range tailModes {
		t.Run(mode.name, func(t *testing.T) {
			test(t, mode)
		})
	}
}

func TestTailModes_BasicTailing(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.log")

		// Create initial file
		err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
		require.NoError(t, err)

		config := fmt.Sprintf(`
mode: %s
filenames:
 - %s%s
`, mode.mode, testFile, mode.extra)

		subLogger := log.WithField("type", "file")

		f := fileacquisition.Source{}
		err = f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		out := make(chan pipeline.Event, 10)

		// Create cancellable context for Stream
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Stream now blocks, so run in goroutine
		go func() {
			_ = f.Stream(streamCtx, out)
		}()

		// Wait for tailing to start
		time.Sleep(300 * time.Millisecond)

		// Verify file is being tailed
		assert.True(t, f.IsTailing(testFile), "File should be tailed")

		// Add new lines
		err = os.WriteFile(testFile, []byte("line1\nline2\nline3\n"), os.ModeAppend)
		require.NoError(t, err)

		// Wait for lines to be read (stat mode needs time to poll)
		time.Sleep(500 * time.Millisecond)

		// Collect events
		var lines []string
		readDone := false
		for !readDone {
			select {
			case evt := <-out:
				lines = append(lines, evt.Line.Raw)
			default:
				readDone = true
			}
		}

		// Cleanup - cancel context to stop Stream
		cancel()

		// Should have read at least one new line (timing-dependent on Windows)
		assert.GreaterOrEqual(t, len(lines), 1, "Should have read at least 1 line")
		// At least one of the new lines should be present
		hasNewLine := false
		for _, line := range lines {
			if line == "line2" || line == "line3" {
				hasNewLine = true
				break
			}
		}
		assert.True(t, hasNewLine, "Should have read at least one new line (line2 or line3)")
	})
}

func TestTailModes_Truncation(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.log")

		// Create initial file
		err := os.WriteFile(testFile, []byte("old1\nold2\nold3\n"), 0o644)
		require.NoError(t, err)

		config := fmt.Sprintf(`
mode: %s
filenames:
 - %s%s
`, mode.mode, testFile, mode.extra)

		subLogger := log.WithField("type", "file")

		f := fileacquisition.Source{}
		err = f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		out := make(chan pipeline.Event, 20)

		// Create cancellable context for Stream
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Stream now blocks, so run in goroutine
		go func() {
			_ = f.Stream(streamCtx, out)
		}()

		// Wait for tailing to start
		time.Sleep(200 * time.Millisecond)

		// Truncate file (simulate rotation)
		err = os.WriteFile(testFile, []byte("new1\n"), 0o644)
		require.NoError(t, err)

		// Wait for truncation detection
		time.Sleep(400 * time.Millisecond)

		// Add more lines
		err = os.WriteFile(testFile, []byte("new1\nnew2\nnew3\n"), os.ModeAppend)
		require.NoError(t, err)

		// Wait for new lines
		time.Sleep(400 * time.Millisecond)

		// Collect events
		var lines []string
		readDone := false
		for !readDone {
			select {
			case evt := <-out:
				lines = append(lines, evt.Line.Raw)
			default:
				readDone = true
			}
		}

		// Cleanup - cancel context to stop Stream
		cancel()

		// Should have detected truncation and read new content
		hasNew := false
		for _, line := range lines {
			if line == "new1" || line == "new2" || line == "new3" {
				hasNew = true
				break
			}
		}
		assert.True(t, hasNew, "Should have read new content after truncation")
	})
}

func TestTailModes_ConfigurationApplied(t *testing.T) {
	// This test verifies that each live mode starts a tail.
	ctx := t.Context()
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		config := fmt.Sprintf("mode: %s\nfilenames:\n - %s%s\n", mode.mode, testFile, mode.extra)
		subLogger := log.WithField("type", "file")

		f := fileacquisition.Source{}
		err := f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		out := make(chan pipeline.Event, 10)

		// Create cancellable context for Stream
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Stream now blocks, so run in goroutine
		go func() {
			_ = f.Stream(streamCtx, out)
		}()

		// Wait for tailing to start
		time.Sleep(200 * time.Millisecond)

		// Add a line to trigger reading
		err = os.WriteFile(testFile, []byte("line1\nline2\n"), os.ModeAppend)
		require.NoError(t, err)

		// Wait for line to be read
		time.Sleep(300 * time.Millisecond)

		// Verify file is being tailed (both modes should work)
		assert.True(t, f.IsTailing(testFile), "File should be tailed")

		// Cleanup - cancel context to stop Stream
		cancel()

		// Mode wiring is covered in config_tail_test.go and the tail package tests.
		t.Logf("Successfully tailed file with mode: %s", mode.name)
	})
}

// TestLiveAcquisitionPartialLine matches the file-tail cases where a write ends
// mid-line: the fragment must not be sent, and the lines written after it must arrive whole.
// Truncation while a fragment is pending drops that fragment.
func TestLiveAcquisitionPartialLine(t *testing.T) {
	const readTimeout = 10 * time.Second
	const quietPeriod = 200 * time.Millisecond

	cases := []struct {
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

	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// nxadm owns line splitting for mode tail. Holding a fragment is the in-house tailer.
		if mode.mode == "tail" {
			t.Skip("nxadm owns line splitting")
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := t.Context()
				testFile := filepath.Join(t.TempDir(), "test.log")

				fd, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
				require.NoError(t, err)
				t.Cleanup(func() { _ = fd.Close() })

				config := fmt.Sprintf("mode: %s\nfilename: '%s'%s", mode.mode, testFile, mode.extra)

				f := fileacquisition.Source{}
				err = f.Configure(ctx, []byte(config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
				require.NoError(t, err)

				out := make(chan pipeline.Event, 8)
				streamCtx, cancel := context.WithCancel(ctx)
				defer cancel()

				go func() {
					_ = f.Stream(streamCtx, out)
				}()

				require.Eventually(t, func() bool {
					if _, err := fd.WriteString("ready\n"); err != nil {
						return false
					}
					select {
					case <-out:
						return true
					case <-time.After(quietPeriod):
						return false
					}
				}, readTimeout, 10*time.Millisecond, "tailer never delivered a line")

				_, err = fd.WriteString("second\n" + `{"a":`)
				require.NoError(t, err)

			waitSecond:
				for {
					select {
					case evt := <-out:
						if evt.Line.Raw == "second" {
							break waitSecond
						}
						require.Equal(t, "ready", evt.Line.Raw)
					case <-time.After(readTimeout):
						t.Fatal("timeout waiting for the line before the partial one")
					}
				}

				if tc.truncate {
					require.NoError(t, fd.Close())
					require.NoError(t, os.Truncate(testFile, 0))
					fd, err = os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
					require.NoError(t, err)
				}

				_, err = fd.WriteString(tc.rest)
				require.NoError(t, err)

				var got []string
				for range tc.expected {
					select {
					case evt := <-out:
						got = append(got, evt.Line.Raw)
					case <-time.After(readTimeout):
						t.Fatalf("timeout waiting for lines, got %q", got)
					}
				}

				select {
				case evt := <-out:
					got = append(got, evt.Line.Raw)
				case <-time.After(quietPeriod):
				}

				require.Equal(t, tc.expected, got)
			})
		}
	})
}

// Five lines written one after another all arrive, in that order, on every live mode.
// The file starts empty, so the end-of-file start still sees each appended line.
func TestTailModes_ContinuousAppend(t *testing.T) {
	expected := []string{"x", "xx", "xxx", "xxxx", "xxxxx"}

	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte(""), 0o644))

		f, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		require.Eventually(t, func() bool {
			return f.IsTailing(testFile)
		}, 5*time.Second, 10*time.Millisecond)

		// nxadm starts its watch after TailFile returns, so a burst written on IsTailing can be missed.
		// A closed append is what that watch observes. Retry until one probe line arrives.
		require.Eventually(t, func() bool {
			if err := appendClosedLine(testFile, "ready"); err != nil {
				return false
			}
			select {
			case evt := <-out:
				return evt.Line.Raw == "ready"
			case <-time.After(200 * time.Millisecond):
				return false
			}
		}, 5*time.Second, 10*time.Millisecond, "tailer never delivered a line")

		for {
			select {
			case evt := <-out:
				require.Equal(t, "ready", evt.Line.Raw)
			case <-time.After(200 * time.Millisecond):
				goto appended
			}
		}
	appended:
		for _, line := range expected {
			require.NoError(t, appendClosedLine(testFile, line))
		}

		var got []string
		for range expected {
			select {
			case evt := <-out:
				got = append(got, evt.Line.Raw)
			case <-time.After(10 * time.Second):
				t.Fatalf("timeout waiting for lines, got %q", got)
			}
		}
		require.Equal(t, expected, got)
	})
}

// Test log rotation by using mv.
func TestTailModes_RenameCreate(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

		_, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		waitUntilFollowed(t, testFile, out)

		require.NoError(t, os.Rename(testFile, testFile+".1"))
		// Longer than the file that was rotated, so a size shrink is not what detects it.
		fresh := strings.Repeat("x", 256)
		require.NoError(t, os.WriteFile(testFile, []byte(fresh+"\n"), 0o644))

		select {
		case evt := <-out:
			require.Equal(t, fresh, evt.Line.Raw)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the line after rename")
		}
	})
}

// A shrink of the same file reopens from the start and delivers the new line.
func TestTailModes_ShrinkReopensFromStart(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("old1\nold2\nold3\n"), 0o644))

		_, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		waitUntilFollowed(t, testFile, out)

		require.NoError(t, os.WriteFile(testFile, []byte("fresh\n"), 0o644))

		select {
		case evt := <-out:
			require.Equal(t, "fresh", evt.Line.Raw)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the line after shrink")
		}
	})
}

// Canceling the stream context stops both live tails.
// nxadm TailFile takes no context, so the file source calls Stop, which closes that follow.
// polltail receives the context, so the same cancel ends its follow directly.
func TestTailModes_ContextCancelStopsTailing(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

		config := fmt.Sprintf("mode: %s\nfilename: '%s'%s", mode.mode, testFile, mode.extra)
		f := &fileacquisition.Source{}
		err := f.Configure(ctx, []byte(config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
		require.NoError(t, err)

		out := make(chan pipeline.Event, 8)
		streamCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)

		streamDone := make(chan struct{})
		go func() {
			_ = f.Stream(streamCtx, out)
			close(streamDone)
		}()

		require.Eventually(t, func() bool {
			return f.IsTailing(testFile)
		}, 5*time.Second, 10*time.Millisecond)

		cancel()

		select {
		case <-streamDone:
		case <-time.After(5 * time.Second):
			t.Fatal("cancel left the tail running")
		}

		require.NoError(t, os.WriteFile(testFile, []byte("old\nafter\n"), 0o644))
		select {
		case evt := <-out:
			t.Fatalf("delivered %q after cancel", evt.Line.Raw)
		case <-time.After(300 * time.Millisecond):
		}
	})
}

// A file that already ends with a newline emits nothing until a new line is appended.
func TestTailModes_StartAtEndOfCompleteFile(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("done\n"), 0o644))

		f, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		require.Eventually(t, func() bool {
			return f.IsTailing(testFile)
		}, 5*time.Second, 10*time.Millisecond)

		select {
		case evt := <-out:
			t.Fatalf("emitted %q from the line already in the file", evt.Line.Raw)
		case <-time.After(1500 * time.Millisecond):
		}

		fd, err := os.OpenFile(testFile, os.O_APPEND|os.O_WRONLY, 0o644)
		require.NoError(t, err)
		_, err = fd.WriteString("next\n")
		require.NoError(t, err)
		require.NoError(t, fd.Close())

		select {
		case evt := <-out:
			require.Equal(t, "next", evt.Line.Raw)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the appended line")
		}

		select {
		case evt := <-out:
			t.Fatalf("extra line %q", evt.Line.Raw)
		case <-time.After(200 * time.Millisecond):
		}
	})
}

// waitUntilFollowed appends probe lines until one is delivered, so the tailer is past startup.
func waitUntilFollowed(t *testing.T, testFile string, out <-chan pipeline.Event) {
	t.Helper()

	require.Eventually(t, func() bool {
		if err := appendClosedLine(testFile, "ready"); err != nil {
			return false
		}
		select {
		case evt := <-out:
			return evt.Line.Raw == "ready"
		case <-time.After(200 * time.Millisecond):
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "tailer never delivered a line")

	for {
		select {
		case evt := <-out:
			require.Equal(t, "ready", evt.Line.Raw)
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}

// streamLiveTail configures one live mode and streams it until cancel.
func streamLiveTail(t *testing.T, ctx context.Context, mode liveTailMode, testFile string) (*fileacquisition.Source, <-chan pipeline.Event, context.CancelFunc) {
	t.Helper()

	config := fmt.Sprintf("mode: %s\nfilename: '%s'%s", mode.mode, testFile, mode.extra)
	f := &fileacquisition.Source{}
	err := f.Configure(ctx, []byte(config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	out := make(chan pipeline.Event, 8)
	streamCtx, cancel := context.WithCancel(ctx)
	go func() {
		_ = f.Stream(streamCtx, out)
	}()
	return f, out, cancel
}

// appendClosedLine appends one line and closes the handle, so a watch that only sees a close still notices the write.
func appendClosedLine(filename string, text string) error {
	fd, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := fd.WriteString(text + "\n")
	closeErr := fd.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
