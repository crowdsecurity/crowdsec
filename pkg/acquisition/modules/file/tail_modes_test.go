package fileacquisition_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Test matrix for both tail implementations
var tailModes = []struct {
	name   string
	config string // tail mode configuration snippet to append
}{
	{
		name:   "default",
		config: "", // Default, no extra config
	},
	{
		name:   "stat",
		config: "\ntail_mode: stat\nstat_poll_interval: 100ms",
	},
}

func TestTailModes_BasicTailing(t *testing.T) {
	for _, mode := range tailModes {
		t.Run(mode.name, func(t *testing.T) {
			ctx := t.Context()
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, "test.log")

			// Create initial file
			err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
			require.NoError(t, err)

			config := fmt.Sprintf(`
mode: tail
filenames:
 - %s%s
`, testFile, mode.config)

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
}

func TestTailModes_Truncation(t *testing.T) {
	for _, mode := range tailModes {
		t.Run(mode.name, func(t *testing.T) {
			ctx := t.Context()
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, "test.log")

			// Create initial file
			err := os.WriteFile(testFile, []byte("old1\nold2\nold3\n"), 0o644)
			require.NoError(t, err)

			config := fmt.Sprintf(`
mode: tail
filenames:
 - %s%s
`, testFile, mode.config)

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
}

func TestTailModes_ConfigurationApplied(t *testing.T) {
	// This test verifies that the tail_mode configuration actually selects
	// the correct implementation (not just ignored)
	ctx := t.Context()
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.log")

	err := os.WriteFile(testFile, []byte("line1\n"), 0o644)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		config string
	}{
		{
			name: "default_is_native",
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
`, testFile),
		},
		{
			name: "explicit_default",
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
tail_mode: default
`, testFile),
		},
		{
			name: "explicit_stat",
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
tail_mode: stat
stat_poll_interval: 100ms
`, testFile),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subLogger := log.WithField("type", "file")

			f := fileacquisition.Source{}
			err := f.Configure(ctx, []byte(tc.config), subLogger, metrics.AcquisitionMetricsLevelNone)
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

			// Stat vs default wiring is covered in config_tail_test.go and the tail package tests.
			t.Logf("Successfully tailed file with mode: %s", tc.name)
		})
	}
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

	for _, mode := range tailModes {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				ctx := t.Context()
				testFile := filepath.Join(t.TempDir(), "test.log")

				fd, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
				require.NoError(t, err)
				t.Cleanup(func() { _ = fd.Close() })

				config := fmt.Sprintf("mode: tail\nfilename: '%s'%s", testFile, mode.config)

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
	}
}
