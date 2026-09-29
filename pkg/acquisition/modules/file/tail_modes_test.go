// This test suite exercises the live tail modes and checks that they behave the same (symmetry)
// tail uses nxadm. The other live mode is polltail.
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
	"github.com/stretchr/testify/require"

	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// liveTailMode is one live file mode. tail uses nxadm. The other live mode is polltail.
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

// A write that ends mid-line is not sent. The lines written after it arrive whole.
// Truncation while a fragment is pending drops that fragment.
// mode tail holds the fragment because nxadm CompleteLines is set. mode polltail leaves it in the file.
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
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Start the tail on an empty file. Each write is closed, so the nxadm watch sees it.
				ctx := t.Context()
				testFile := filepath.Join(t.TempDir(), "test.log")
				require.NoError(t, os.WriteFile(testFile, nil, 0o644))

				_, out, cancel := streamLiveTail(t, ctx, mode, testFile)
				defer cancel()

				// Wait until a complete line is delivered, so the tail is running.
				require.Eventually(t, func() bool {
					if err := appendClosedLine(testFile, "ready"); err != nil {
						return false
					}
					select {
					case <-out:
						return true
					case <-time.After(quietPeriod):
						return false
					}
				}, readTimeout, 10*time.Millisecond, "tailer never delivered a line")

				// Write one complete line and a fragment with no newline.
				require.NoError(t, appendClosedBytes(testFile, "second\n"+`{"a":`))

				// The complete line arrives. The fragment does not.
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

				// The truncated case replaces the file while that fragment is still held.
				if tc.truncate {
					require.NoError(t, os.Truncate(testFile, 0))
				}

				// Write the rest of the line, or the new file.
				require.NoError(t, appendClosedBytes(testFile, tc.rest))

				// Those lines arrive, and nothing else does.
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

// Successive appends all arrive, in order. An empty file followed from the end still sees those writes.
func TestTailModes_ContinuousAppend(t *testing.T) {
	expected := []string{"x", "xx", "xxx", "xxxx", "xxxxx"}

	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// Start on an empty file and wait until it is being tailed.
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

		// Drop any extra probe lines.
		for {
			select {
			case evt := <-out:
				require.Equal(t, "ready", evt.Line.Raw)
			case <-time.After(200 * time.Millisecond):
				goto appended
			}
		}
	appended:
		// Append the lines one after another.
		for _, line := range expected {
			require.NoError(t, appendClosedLine(testFile, line))
		}

		// They arrive in that order.
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

// A renamed file is left behind. The new file at the same path is read from the start even when it is larger, so a shrink is not what detects the replacement.
func TestTailModes_RenameCreate(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// Start on a file that already has a line, and wait until the tail is past startup.
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("old\n"), 0o644))

		_, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		waitUntilFollowed(t, testFile, out)

		// Rename it away and put a longer file at the same path.
		require.NoError(t, os.Rename(testFile, testFile+".1"))
		// Longer than the file that was rotated, so a size shrink is not what detects it.
		fresh := strings.Repeat("x", 256)
		require.NoError(t, os.WriteFile(testFile, []byte(fresh+"\n"), 0o644))

		// That new line arrives.
		select {
		case evt := <-out:
			require.Equal(t, fresh, evt.Line.Raw)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the line after rename")
		}
	})
}

// A shrink of the same file is read from the start.
func TestTailModes_ShrinkReopensFromStart(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// Start on a file that already has lines, and wait until the tail is past startup.
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("old1\nold2\nold3\n"), 0o644))

		_, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		waitUntilFollowed(t, testFile, out)

		// Replace it with a shorter file.
		require.NoError(t, os.WriteFile(testFile, []byte("fresh\n"), 0o644))

		// The new line arrives.
		select {
		case evt := <-out:
			require.Equal(t, "fresh", evt.Line.Raw)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the line after shrink")
		}
	})
}

// Canceling the stream context makes Stream return on both live modes, and a line written after that is not delivered.
// nxadm TailFile takes no context, so the file source calls Stop. polltail receives the context, so the same cancel ends its follow directly.
func TestTailModes_ContextCancelStopsTailing(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// Start the tail and wait until the file is being followed.
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

		// Cancel the stream.
		cancel()

		// Stream returns, and a line written after that is not delivered.
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

// A file that already ends with a newline emits nothing until a new line is appended, and that line arrives once.
func TestTailModes_StartAtEndOfCompleteFile(t *testing.T) {
	forEachLiveTailMode(t, func(t *testing.T, mode liveTailMode) {
		// Start at the end of a file that already ends with a newline.
		ctx := t.Context()
		testFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(testFile, []byte("done\n"), 0o644))

		f, out, cancel := streamLiveTail(t, ctx, mode, testFile)
		defer cancel()

		require.Eventually(t, func() bool {
			return f.IsTailing(testFile)
		}, 5*time.Second, 10*time.Millisecond)

		// Nothing already in the file is emitted.
		select {
		case evt := <-out:
			t.Fatalf("emitted %q from the line already in the file", evt.Line.Raw)
		case <-time.After(1500 * time.Millisecond):
		}

		// Append one line. It arrives once.
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
	return appendClosedBytes(filename, text+"\n")
}

// appendClosedBytes appends text and closes the handle, so a watch that only sees a close still notices the write.
func appendClosedBytes(filename string, text string) error {
	fd, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := fd.WriteString(text)
	closeErr := fd.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
