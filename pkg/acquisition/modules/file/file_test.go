package fileacquisition_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestConfigureDSN(t *testing.T) {
	ctx := t.Context()

	file := "/etc/passwd"

	if runtime.GOOS == "windows" {
		file = `C:\Windows\System32\drivers\etc\hosts`
	}

	tests := []struct {
		dsn         string
		expectedErr string
	}{
		{
			dsn:         "asd://",
			expectedErr: "invalid DSN asd:// for file source, must start with file://",
		},
		{
			dsn:         "file://",
			expectedErr: "empty file:// DSN",
		},
		{
			dsn: fmt.Sprintf("file://%s?log_level=warn", file),
		},
		{
			dsn:         fmt.Sprintf("file://%s?log_level=foobar", file),
			expectedErr: "unknown level foobar: not a valid logrus Level:",
		},
	}

	subLogger := log.WithField("type", fileacquisition.ModuleName)

	for _, tc := range tests {
		t.Run(tc.dsn, func(t *testing.T) {
			f := fileacquisition.Source{}
			err := f.ConfigureByDSN(ctx, tc.dsn, map[string]string{"type": "testtype"}, subLogger, "")
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestOneShot(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	deletedFile := filepath.Join(tmpDir, "test_delete.log")

	permDeniedFile := "/etc/shadow"
	permDeniedError := "failed opening /etc/shadow: open /etc/shadow: permission denied"

	if runtime.GOOS == "windows" {
		// Technically, this is not a permission denied error, but we just want to test what happens
		// if we do not have access to the file
		permDeniedFile = `C:\Windows\System32\config\SAM`
		permDeniedError = `failed opening C:\Windows\System32\config\SAM: open C:\Windows\System32\config\SAM: The process cannot access the file because it is being used by another process.`
	}

	tests := []struct {
		name              string
		config            string
		expectedConfigErr string
		expectedErr       string
		expectedOutput    string
		expectedLines     int
		logLevel          log.Level
		setup             func()
		afterConfigure    func()
		teardown          func()
	}{
		{
			name: "permission denied",
			config: fmt.Sprintf(`
mode: cat
filename: %s`, permDeniedFile),
			expectedErr:   permDeniedError,
			logLevel:      log.WarnLevel,
			expectedLines: 0,
		},
		{
			name: "ignored directory",
			config: `
mode: cat
filename: /`,
			expectedOutput: "/ is a directory, ignoring it",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			name: "glob syntax error",
			config: `
mode: cat
filename: "[*-.log"`,
			expectedConfigErr: "glob failure: syntax error in pattern",
			logLevel:          log.WarnLevel,
			expectedLines:     0,
		},
		{
			name: "no matching files",
			config: `
mode: cat
filename: /do/not/exist`,
			expectedOutput: "No matching files for pattern /do/not/exist",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			name: "test.log",
			config: `
mode: cat
filename: testdata/test.log`,
			expectedLines: 5,
			logLevel:      log.WarnLevel,
		},
		{
			name: "test.log.gz",
			config: `
mode: cat
filename: testdata/test.log.gz`,
			expectedLines: 5,
			logLevel:      log.WarnLevel,
		},
		{
			name: "unexpected end of gzip stream",
			config: `
mode: cat
filename: testdata/bad.gz`,
			expectedErr:   "failed to read gz testdata/bad.gz: unexpected EOF",
			expectedLines: 0,
			logLevel:      log.WarnLevel,
		},
		{
			name: "deleted file",
			config: fmt.Sprintf(`
mode: cat
filename: %s`, deletedFile),
			setup: func() {
				f, _ := os.Create(deletedFile)
				f.Close()
			},
			afterConfigure: func() {
				os.Remove(deletedFile)
			},
			expectedErr: "could not stat file " + deletedFile,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(tc.logLevel)

			subLogger := logger.WithField("type", fileacquisition.ModuleName)

			out := make(chan pipeline.Event, 100)
			f := fileacquisition.Source{}

			if tc.setup != nil {
				tc.setup()
			}

			err := f.Configure(ctx, []byte(tc.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, tc.expectedConfigErr)

			if tc.expectedConfigErr != "" {
				return
			}

			if tc.afterConfigure != nil {
				tc.afterConfigure()
			}

			err = f.OneShot(ctx, out)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedLines != 0 {
				assert.Len(t, out, tc.expectedLines)
			}

			if tc.expectedOutput != "" {
				assert.Contains(t, hook.LastEntry().Message, tc.expectedOutput)
				hook.Reset()
			}

			if tc.teardown != nil {
				tc.teardown()
			}
		})
	}
}

func TestLiveAcquisition(t *testing.T) {
	ctx := t.Context()
	permDeniedFile := "/etc/shadow"
	permDeniedError := "unable to read /etc/shadow : open /etc/shadow: permission denied"
	tmpDir := t.TempDir()
	testPattern := filepath.Join(tmpDir, "*.log")

	if runtime.GOOS == "windows" {
		// Technically, this is not a permission denied error, but we just want to test what happens
		// if we do not have access to the file
		permDeniedFile = `C:\Windows\System32\config\SAM`
		permDeniedError = `unable to read C:\Windows\System32\config\SAM : open C:\Windows\System32\config\SAM: The process cannot access the file because it is being used by another process`
	}

	tests := []struct {
		name           string
		config         string
		expectedErr    string
		expectedOutput string
		expectedLines  int
		logLevel       log.Level
		setup          func()
		afterConfigure func()
		teardown       func()
	}{
		{
			config: fmt.Sprintf(`
mode: tail
filename: %s`, permDeniedFile),
			expectedOutput: permDeniedError,
			logLevel:       log.InfoLevel,
			expectedLines:  0,
			name:           "PermissionDenied",
		},
		{
			config: `
mode: tail
filename: /`,
			expectedOutput: "/ is a directory, ignoring it",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
			name:           "Directory",
		},
		{
			config: `
mode: tail
filename: /do/not/exist`,
			expectedOutput: "No matching files for pattern /do/not/exist",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
			name:           "badPattern",
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedLines: 5,
			logLevel:      log.DebugLevel,
			name:          "basicGlob",
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedLines: 0,
			logLevel:      log.DebugLevel,
			name:          "GlobInotify",
			afterConfigure: func() {
				f, _ := os.Create(filepath.Join(tmpDir, "a.log"))
				f.Close()
				time.Sleep(1 * time.Second)
				os.Remove(f.Name())
			},
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedLines: 5,
			logLevel:      log.DebugLevel,
			name:          "GlobInotifyChmod",
			afterConfigure: func() {
				f, err := os.Create(filepath.Join(tmpDir, "a.log"))
				require.NoError(t, err)
				err = f.Close()
				require.NoError(t, err)
				time.Sleep(1 * time.Second)
				err = os.Chmod(f.Name(), 0o000)
				require.NoError(t, err)
			},
			teardown: func() {
				err := os.Chmod(filepath.Join(tmpDir, "a.log"), 0o644)
				require.NoError(t, err)
				err = os.Remove(filepath.Join(tmpDir, "a.log"))
				require.NoError(t, err)
			},
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedLines: 5,
			logLevel:      log.DebugLevel,
			name:          "InotifyMkDir",
			afterConfigure: func() {
				err := os.Mkdir(filepath.Join(tmpDir, "pouet"), 0o700)
				require.NoError(t, err)
			},
			teardown: func() {
				os.Remove(filepath.Join(tmpDir, "pouet"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(tc.logLevel)

			subLogger := logger.WithField("type", fileacquisition.ModuleName)

			tomb := tomb.Tomb{}
			out := make(chan pipeline.Event)

			f := fileacquisition.Source{}

			if tc.setup != nil {
				tc.setup()
			}

			err := f.Configure(ctx, []byte(tc.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			if tc.afterConfigure != nil {
				tc.afterConfigure()
			}

			var actualLines atomic.Int32

			if tc.expectedLines != 0 {
				var stopReading atomic.Bool
				defer func() { stopReading.Store(true) }()

				go func() {
					for {
						select {
						case <-out:
							actualLines.Add(1)
						default:
							if stopReading.Load() {
								return
							}
							// Small sleep to prevent tight loop
							time.Sleep(100 * time.Millisecond)
						}
					}
				}()
			}

			err = f.StreamingAcquisition(ctx, out, &tomb)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedLines != 0 {
				// f.IsTailing is path delimiter sensitive
				streamLogFile := filepath.Join(tmpDir, "stream.log")

				fd, err := os.Create(streamLogFile)
				require.NoError(t, err, "could not create test file")

				// wait for the file to be tailed
				waitingForTail := true
				for waitingForTail {
					select {
					case <-time.After(2 * time.Second):
						t.Fatal("Timeout waiting for file to be tailed")
					default:
						if !f.IsTailing(streamLogFile) {
							time.Sleep(50 * time.Millisecond)
							continue
						}

						waitingForTail = false
					}
				}

				for i := range 5 {
					_, err = fmt.Fprintf(fd, "%d\n", i)
					if err != nil {
						os.Remove(streamLogFile)
						t.Fatalf("could not write test file : %s", err)
					}
				}

				fd.Close()

				// sleep to ensure the tail events are processed
				time.Sleep(2 * time.Second)

				os.Remove(streamLogFile)
				assert.Equal(t, tc.expectedLines, int(actualLines.Load()))
			}

			if tc.expectedOutput != "" {
				if hook.LastEntry() == nil {
					t.Fatalf("expected output %s, but got nothing", tc.expectedOutput)
				}

				assert.Contains(t, hook.LastEntry().Message, tc.expectedOutput)
				hook.Reset()
			}

			if tc.teardown != nil {
				tc.teardown()
			}

			tomb.Kill(nil)
		})
	}
}

func TestExclusion(t *testing.T) {
	ctx := t.Context()

	config := `filenames: ["testdata/*.log*"]
exclude_regexps: ["\\.gz$"]`
	logger, hook := test.NewNullLogger()
	// logger.SetLevel(ts.logLevel)
	subLogger := logger.WithField("type", fileacquisition.ModuleName)

	f := fileacquisition.Source{}
	err := f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	require.NotNil(t, hook.LastEntry())
	assert.Contains(t, hook.LastEntry().Message, `Skipping file: matches exclude regex "\\.gz`)
	assert.Equal(t, filepath.Join("testdata", "test.log.gz"), hook.LastEntry().Data["file"])
	hook.Reset()
}

func TestDiscoveryPolling(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()

	pattern := filepath.Join(dir, "*.log")
	yamlConfig := fmt.Sprintf(`
filenames:
 - '%s'
discovery_poll_enable: true
discovery_poll_interval: "1s"
exclude_regexps: ["\\.ignore$"]
mode: tail
`, pattern)

	fmt.Printf("Config: %s\n", yamlConfig)
	config := []byte(yamlConfig)

	f := &fileacquisition.Source{}
	err := f.Configure(ctx, config, log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	// Create channel for events
	eventChan := make(chan pipeline.Event)
	tomb := tomb.Tomb{}

	// Start acquisition
	err = f.StreamingAcquisition(ctx, eventChan, &tomb)
	require.NoError(t, err)

	// Create a test file
	testFile := filepath.Join(dir, "test.log")
	err = os.WriteFile(testFile, []byte("test line\n"), 0o644)
	require.NoError(t, err)

	ignoredFile := filepath.Join(dir, ".ignored")
	err = os.WriteFile(ignoredFile, []byte("test line\n"), 0o644)
	require.NoError(t, err)

	// Wait for polling to detect the file
	time.Sleep(4 * time.Second)

	require.True(t, f.IsTailing(testFile), "File should be tailed after polling")
	require.False(t, f.IsTailing(ignoredFile), "File should be ignored after polling")

	// Cleanup
	tomb.Kill(nil)
	require.NoError(t, tomb.Wait())
}

func TestFileResurrectionViaPolling(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()

	testFile := filepath.Join(dir, "test.log")
	err := os.WriteFile(testFile, []byte("test line\n"), 0o644)
	require.NoError(t, err)

	pattern := filepath.Join(dir, "*.log")
	yamlConfig := fmt.Sprintf(`
filenames:
 - '%s'
discovery_poll_enable: true
discovery_poll_interval: "1s"
mode: tail
`, pattern)

	fmt.Printf("Config: %s\n", yamlConfig)
	config := []byte(yamlConfig)

	f := &fileacquisition.Source{}
	err = f.Configure(ctx, config, log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	eventChan := make(chan pipeline.Event)
	tomb := tomb.Tomb{}

	err = f.StreamingAcquisition(ctx, eventChan, &tomb)
	require.NoError(t, err)

	// Wait for initial tail setup
	time.Sleep(100 * time.Millisecond)

	// Simulate tailer death by removing it from the map
	f.RemoveTail(testFile)
	isTailed := f.IsTailing(testFile)
	require.False(t, isTailed, "File should be removed from the map")

	// Wait for polling to resurrect the file
	time.Sleep(2 * time.Second)

	// Verify file is being tailed again
	isTailed = f.IsTailing(testFile)
	require.True(t, isTailed, "File should be resurrected via polling")

	// Cleanup
	tomb.Kill(nil)
	require.NoError(t, tomb.Wait())
}

// The tailer can reach EOF in the middle of a line, for instance when a write
// crosses a page boundary: the partial line must not be sent on its own, and
// the lines written after it must not be skipped.
func TestLiveAcquisitionPartialLine(t *testing.T) {
	ctx := t.Context()

	// Generous on purpose, so that a slow machine doesn't turn into a test failure
	const readTimeout = 10 * time.Second
	// How long we wait to confirm that no extra line shows up
	const quietPeriod = 100 * time.Millisecond

	tests := []struct {
		name     string
		truncate bool   // truncate the file while the partial line is pending
		rest     string // written after the partial line
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testFile := filepath.Join(t.TempDir(), "test.log")

			fd, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			require.NoError(t, err)

			defer fd.Close()

			config := fmt.Sprintf("mode: tail\nfilename: '%s'", testFile)

			f := fileacquisition.Source{}
			err = f.Configure(ctx, []byte(config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			out := make(chan pipeline.Event)
			tomb := tomb.Tomb{}

			err = f.StreamingAcquisition(ctx, out, &tomb)
			require.NoError(t, err)

			t.Cleanup(func() { tomb.Kill(nil) })

			// The tailer seeks to the end when it opens the file, which may not have
			// happened yet: write markers until one comes back.
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

			// Skip leftover markers. "second" means the tailer has read that write
			// and now sits on the partial line.
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
				require.NoError(t, os.Truncate(testFile, 0))
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
