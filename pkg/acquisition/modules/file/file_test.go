package fileacquisition_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestBadConfiguration(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name:        "extra configuration key",
			config:      "foobar: asd.log",
			expectedErr: `cannot parse FileAcquisition configuration: [1:1] unknown field "foobar"`,
		},
		{
			name:        "missing filenames",
			config:      "mode: tail",
			expectedErr: "no filename or filenames configuration provided",
		},
		{
			name:        "glob syntax error",
			config:      `filename: "[asd-.log"`,
			expectedErr: "glob failure: syntax error in pattern",
		},
		{
			name: "bad exclude regexp",
			config: `filenames: ["asd.log"]
exclude_regexps: ["as[a-$d"]`,
			expectedErr: "could not compile regexp as",
		},
		{
			name: "duplicate keys",
			config: `filenames: ["asd.log"]
filenames: ["ase.log"]`,
			expectedErr: `cannot parse FileAcquisition configuration: [2:1] mapping key "filenames" already defined at [1:1]`,
		},
	}

	subLogger := log.WithField("type", "file")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := fileacquisition.FileSource{}
			err := f.Configure(ctx, []byte(tc.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

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

	subLogger := log.WithField("type", "file")

	for _, tc := range tests {
		t.Run(tc.dsn, func(t *testing.T) {
			f := fileacquisition.FileSource{}
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

			subLogger := logger.WithField("type", "file")

			tomb := tomb.Tomb{}
			out := make(chan types.Event, 100)
			f := fileacquisition.FileSource{}

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

			err = f.OneShotAcquisition(ctx, out, &tomb)
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

			subLogger := logger.WithField("type", "file")

			tomb := tomb.Tomb{}
			out := make(chan types.Event)

			f := fileacquisition.FileSource{}

			if tc.setup != nil {
				tc.setup()
			}

			err := f.Configure(ctx, []byte(tc.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			if tc.afterConfigure != nil {
				tc.afterConfigure()
			}

			actualLines := 0

			if tc.expectedLines != 0 {
				var stopReading bool
				defer func() { stopReading = true }()

				go func() {
					for {
						select {
						case <-out:
							actualLines++
						default:
							if stopReading {
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
				assert.Equal(t, tc.expectedLines, actualLines)
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
	subLogger := logger.WithField("type", "file")

	f := fileacquisition.FileSource{}
	err := f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	require.NotNil(t, hook.LastEntry())
	assert.Contains(t, hook.LastEntry().Message, `Skipping file: matches exclude regex "\\.gz`)
	assert.Equal(t, filepath.Join("testdata", "test.log.gz"), hook.LastEntry().Data["file"])
	hook.Reset()
}

func TestDiscoveryPollConfiguration(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "valid discovery poll config",
			config: `
filenames:
 - "tests/test.log"
discovery_poll_enable: true
discovery_poll_interval: "30s"
mode: tail
`,
			wantErr: "",
		},
		{
			name: "invalid poll interval",
			config: `
filenames:
 - "tests/test.log"
discovery_poll_enable: true
discovery_poll_interval: "invalid"
mode: tail
`,
			wantErr: `cannot parse FileAcquisition configuration: time: invalid duration "invalid"`,
		},
		{
			name: "polling disabled",
			config: `
filenames:
 - "tests/test.log"
discovery_poll_enable: false
mode: tail
`,
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fileacquisition.FileSource{}
			err := f.Configure(ctx, []byte(tc.config), log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
			cstest.RequireErrorContains(t, err, tc.wantErr)
		})
	}
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

	f := &fileacquisition.FileSource{}
	err := f.Configure(ctx, config, log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	// Create channel for events
	eventChan := make(chan types.Event)
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

	f := &fileacquisition.FileSource{}
	err = f.Configure(ctx, config, log.NewEntry(log.New()), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	eventChan := make(chan types.Event)
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
