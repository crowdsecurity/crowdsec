package fileacquisition_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestBadConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name:        "extra configuration key",
			config:      "foobar: asd.log",
			expectedErr: "line 1: field foobar not found in type fileacquisition.FileConfiguration",
		},
		{
			name:        "missing filenames",
			config:      "mode: tail",
			expectedErr: "no filename or filenames configuration provided",
		},
		{
			name:        "glob syntax error",
			config:      `filename: "[asd-.log"`,
			expectedErr: "Glob failure: syntax error in pattern",
		},
		{
			name: "bad exclude regexp",
			config: `filenames: ["asd.log"]
exclude_regexps: ["as[a-$d"]`,
			expectedErr: "could not compile regexp as",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "file",
	})

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := fileacquisition.FileSource{}
			err := f.Configure([]byte(tc.config), subLogger)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestConfigureDSN(t *testing.T) {
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

	subLogger := log.WithFields(log.Fields{
		"type": "file",
	})

	for _, tc := range tests {
		tc := tc
		t.Run(tc.dsn, func(t *testing.T) {
			f := fileacquisition.FileSource{}
			err := f.ConfigureByDSN(tc.dsn, map[string]string{"type": "testtype"}, subLogger, "")
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestOneShot(t *testing.T) {
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
			expectedConfigErr: "Glob failure: syntax error in pattern",
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
filename: test_files/test.log`,
			expectedLines: 5,
			logLevel:      log.WarnLevel,
		},
		{
			name: "test.log.gz",
			config: `
mode: cat
filename: test_files/test.log.gz`,
			expectedLines: 5,
			logLevel:      log.WarnLevel,
		},
		{
			name: "unexpected end of gzip stream",
			config: `
mode: cat
filename: test_files/bad.gz`,
			expectedErr:   "failed to read gz test_files/bad.gz: unexpected EOF",
			expectedLines: 0,
			logLevel:      log.WarnLevel,
		},
		{
			name: "deleted file",
			config: `
mode: cat
filename: test_files/test_delete.log`,
			setup: func() {
				f, _ := os.Create("test_files/test_delete.log")
				f.Close()
			},
			afterConfigure: func() {
				os.Remove("test_files/test_delete.log")
			},
			expectedErr: "could not stat file test_files/test_delete.log",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(tc.logLevel)

			subLogger := logger.WithFields(log.Fields{
				"type": "file",
			})

			tomb := tomb.Tomb{}
			out := make(chan types.Event, 100)
			f := fileacquisition.FileSource{}

			if tc.setup != nil {
				tc.setup()
			}

			err := f.Configure([]byte(tc.config), subLogger)
			cstest.RequireErrorContains(t, err, tc.expectedConfigErr)
			if tc.expectedConfigErr != "" {
				return
			}

			if tc.afterConfigure != nil {
				tc.afterConfigure()
			}
			err = f.OneShotAcquisition(out, &tomb)
			actualLines := len(out)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedLines != 0 {
				assert.Equal(t, tc.expectedLines, actualLines)
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
	permDeniedFile := "/etc/shadow"
	permDeniedError := "unable to read /etc/shadow : open /etc/shadow: permission denied"
	testPattern := "test_files/*.log"

	if runtime.GOOS == "windows" {
		// Technically, this is not a permission denied error, but we just want to test what happens
		// if we do not have access to the file
		permDeniedFile = `C:\Windows\System32\config\SAM`
		permDeniedError = `unable to read C:\Windows\System32\config\SAM : open C:\Windows\System32\config\SAM: The process cannot access the file because it is being used by another process`
		testPattern = `test_files\\*.log` // the \ must be escaped for the yaml config
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
				f, _ := os.Create("test_files/a.log")
				f.Close()
				time.Sleep(1 * time.Second)
				os.Remove("test_files/a.log")
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
				f, _ := os.Create("test_files/a.log")
				f.Close()
				time.Sleep(1 * time.Second)
				os.Chmod("test_files/a.log", 0o000)
			},
			teardown: func() {
				os.Chmod("test_files/a.log", 0o644)
				os.Remove("test_files/a.log")
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
				os.Mkdir("test_files/pouet/", 0o700)
			},
			teardown: func() {
				os.Remove("test_files/pouet/")
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(tc.logLevel)

			subLogger := logger.WithFields(log.Fields{
				"type": "file",
			})

			tomb := tomb.Tomb{}
			out := make(chan types.Event)

			f := fileacquisition.FileSource{}

			if tc.setup != nil {
				tc.setup()
			}

			err := f.Configure([]byte(tc.config), subLogger)
			require.NoError(t, err)

			if tc.afterConfigure != nil {
				tc.afterConfigure()
			}

			actualLines := 0
			if tc.expectedLines != 0 {
				go func() {
					for {
						select {
						case <-out:
							actualLines++
						case <-time.After(2 * time.Second):
							return
						}
					}
				}()
			}

			err = f.StreamingAcquisition(out, &tomb)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedLines != 0 {
				fd, err := os.Create("test_files/stream.log")
				if err != nil {
					t.Fatalf("could not create test file : %s", err)
				}

				for i := 0; i < 5; i++ {
					_, err = fmt.Fprintf(fd, "%d\n", i)
					if err != nil {
						t.Fatalf("could not write test file : %s", err)
						os.Remove("test_files/stream.log")
					}
				}

				fd.Close()
				// we sleep to make sure we detect the new file
				time.Sleep(1 * time.Second)
				os.Remove("test_files/stream.log")
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
	config := `filenames: ["test_files/*.log*"]
exclude_regexps: ["\\.gz$"]`
	logger, hook := test.NewNullLogger()
	// logger.SetLevel(ts.logLevel)
	subLogger := logger.WithFields(log.Fields{
		"type": "file",
	})

	f := fileacquisition.FileSource{}
	if err := f.Configure([]byte(config), subLogger); err != nil {
		subLogger.Fatalf("unexpected error: %s", err)
	}

	expectedLogOutput := "Skipping file test_files/test.log.gz as it matches exclude pattern"

	if runtime.GOOS == "windows" {
		expectedLogOutput = `Skipping file test_files\test.log.gz as it matches exclude pattern \.gz`
	}

	if hook.LastEntry() == nil {
		t.Fatalf("expected output %s, but got nothing", expectedLogOutput)
	}

	assert.Contains(t, hook.LastEntry().Message, expectedLogOutput)
	hook.Reset()
}
