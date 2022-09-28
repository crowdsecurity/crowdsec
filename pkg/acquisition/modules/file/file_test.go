package fileacquisition

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func TestBadConfiguration(t *testing.T) {
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd.log`,
			expectedErr: "line 1: field foobar not found in type fileacquisition.FileConfiguration",
		},
		{
			config:      `mode: tail`,
			expectedErr: "no filename or filenames configuration provided",
		},
		{
			config:      `filename: "[asd-.log"`,
			expectedErr: "Glob failure: syntax error in pattern",
		},
		{
			config: `filenames: ["asd.log"]
exclude_regexps: ["as[a-$d"]`,
			expectedErr: "Could not compile regexp as",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "file",
	})
	for _, test := range tests {
		f := FileSource{}
		err := f.Configure([]byte(test.config), subLogger)
		assert.Contains(t, err.Error(), test.expectedErr)
	}
}

func TestConfigureDSN(t *testing.T) {
	var file string
	if runtime.GOOS != "windows" {
		file = "/etc/passwd"
	} else {
		file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
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
			dsn:         fmt.Sprintf("file://%s?log_level=warn", file),
			expectedErr: "",
		},
		{
			dsn:         fmt.Sprintf("file://%s?log_level=foobar", file),
			expectedErr: "unknown level foobar: not a valid logrus Level:",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "file",
	})
	for _, test := range tests {
		f := FileSource{}
		err := f.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestOneShot(t *testing.T) {
	var permDeniedFile string
	var permDeniedError string
	if runtime.GOOS != "windows" {
		permDeniedFile = "/etc/shadow"
		permDeniedError = "failed opening /etc/shadow: open /etc/shadow: permission denied"
	} else {
		//Technically, this is not a permission denied error, but we just want to test what happens
		//if we do not have access to the file
		permDeniedFile = "C:\\Windows\\System32\\config\\SAM"
		permDeniedError = "failed opening C:\\Windows\\System32\\config\\SAM: open C:\\Windows\\System32\\config\\SAM: The process cannot access the file because it is being used by another process."
	}
	tests := []struct {
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
			config: fmt.Sprintf(`
mode: cat
filename: %s`, permDeniedFile),
			expectedConfigErr: "",
			expectedErr:       permDeniedError,
			expectedOutput:    "",
			logLevel:          log.WarnLevel,
			expectedLines:     0,
		},
		{
			config: `
mode: cat
filename: /`,
			expectedConfigErr: "",
			expectedErr:       "",
			expectedOutput:    "/ is a directory, ignoring it",
			logLevel:          log.WarnLevel,
			expectedLines:     0,
		},
		{
			config: `
mode: cat
filename: "[*-.log"`,
			expectedConfigErr: "Glob failure: syntax error in pattern",
			expectedErr:       "",
			expectedOutput:    "",
			logLevel:          log.WarnLevel,
			expectedLines:     0,
		},
		{
			config: `
mode: cat
filename: /do/not/exist`,
			expectedConfigErr: "",
			expectedErr:       "",
			expectedOutput:    "No matching files for pattern /do/not/exist",
			logLevel:          log.WarnLevel,
			expectedLines:     0,
		},
		{
			config: `
mode: cat
filename: test_files/test.log`,
			expectedConfigErr: "",
			expectedErr:       "",
			expectedOutput:    "",
			expectedLines:     5,
			logLevel:          log.WarnLevel,
		},
		{
			config: `
mode: cat
filename: test_files/test.log.gz`,
			expectedConfigErr: "",
			expectedErr:       "",
			expectedOutput:    "",
			expectedLines:     5,
			logLevel:          log.WarnLevel,
		},
		{
			config: `
mode: cat
filename: test_files/bad.gz`,
			expectedConfigErr: "",
			expectedErr:       "failed to read gz test_files/bad.gz: unexpected EOF",
			expectedOutput:    "",
			expectedLines:     0,
			logLevel:          log.WarnLevel,
		},
		{
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

	for _, ts := range tests {
		logger, hook := test.NewNullLogger()
		logger.SetLevel(ts.logLevel)
		subLogger := logger.WithFields(log.Fields{
			"type": "file",
		})
		tomb := tomb.Tomb{}
		out := make(chan types.Event)
		f := FileSource{}
		if ts.setup != nil {
			ts.setup()
		}
		err := f.Configure([]byte(ts.config), subLogger)
		cstest.AssertErrorContains(t, err, ts.expectedConfigErr)
		if err != nil {
			continue
		}

		if ts.afterConfigure != nil {
			ts.afterConfigure()
		}
		actualLines := 0
		if ts.expectedLines != 0 {
			go func() {
			READLOOP:
				for {
					select {
					case <-out:
						actualLines++
					case <-time.After(1 * time.Second):
						break READLOOP
					}
				}
			}()
		}
		err = f.OneShotAcquisition(out, &tomb)
		cstest.AssertErrorContains(t, err, ts.expectedErr)

		if ts.expectedLines != 0 {
			assert.Equal(t, actualLines, ts.expectedLines)
		}
		if ts.expectedOutput != "" {
			assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
			hook.Reset()
		}
		if ts.teardown != nil {
			ts.teardown()
		}
	}
}

func TestLiveAcquisition(t *testing.T) {
	var permDeniedFile string
	var permDeniedError string
	var testPattern string
	if runtime.GOOS != "windows" {
		permDeniedFile = "/etc/shadow"
		permDeniedError = "unable to read /etc/shadow : open /etc/shadow: permission denied"
		testPattern = "test_files/*.log"
	} else {
		//Technically, this is not a permission denied error, but we just want to test what happens
		//if we do not have access to the file
		permDeniedFile = "C:\\Windows\\System32\\config\\SAM"
		permDeniedError = "unable to read C:\\Windows\\System32\\config\\SAM : open C:\\Windows\\System32\\config\\SAM: The process cannot access the file because it is being used by another process"
		testPattern = "test_files\\\\*.log" // the \ must be escaped twice: once for the string, once for the yaml config
	}
	tests := []struct {
		config         string
		expectedErr    string
		expectedOutput string
		name           string
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
			expectedErr:    "",
			expectedOutput: permDeniedError,
			logLevel:       log.InfoLevel,
			expectedLines:  0,
			name:           "PermissionDenied",
		},
		{
			config: `
mode: tail
filename: /`,
			expectedErr:    "",
			expectedOutput: "/ is a directory, ignoring it",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
			name:           "Directory",
		},
		{
			config: `
mode: tail
filename: /do/not/exist`,
			expectedErr:    "",
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
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
			name:           "basicGlob",
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  0,
			logLevel:       log.DebugLevel,
			name:           "GlobInotify",
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
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
			name:           "GlobInotifyChmod",
			afterConfigure: func() {
				f, _ := os.Create("test_files/a.log")
				f.Close()
				time.Sleep(1 * time.Second)
				os.Chmod("test_files/a.log", 0000)
			},
			teardown: func() {
				os.Chmod("test_files/a.log", 0644)
				os.Remove("test_files/a.log")
			},
		},
		{
			config: fmt.Sprintf(`
mode: tail
filenames:
 - %s
force_inotify: true`, testPattern),
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
			name:           "InotifyMkDir",
			afterConfigure: func() {
				os.Mkdir("test_files/pouet/", 0700)
			},
			teardown: func() {
				os.Remove("test_files/pouet/")
			},
		},
	}

	for _, ts := range tests {
		t.Logf("test: %s", ts.name)
		logger, hook := test.NewNullLogger()
		logger.SetLevel(ts.logLevel)
		subLogger := logger.WithFields(log.Fields{
			"type": "file",
		})
		tomb := tomb.Tomb{}
		out := make(chan types.Event)
		f := FileSource{}
		if ts.setup != nil {
			ts.setup()
		}
		err := f.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		if ts.afterConfigure != nil {
			ts.afterConfigure()
		}
		actualLines := 0
		if ts.expectedLines != 0 {
			go func() {
			READLOOP:
				for {
					select {
					case <-out:
						actualLines++
					case <-time.After(2 * time.Second):
						break READLOOP
					}
				}
			}()
		}
		err = f.StreamingAcquisition(out, &tomb)
		cstest.AssertErrorContains(t, err, ts.expectedErr)

		if ts.expectedLines != 0 {
			fd, err := os.Create("test_files/stream.log")
			if err != nil {
				t.Fatalf("could not create test file : %s", err)
			}
			for i := 0; i < 5; i++ {
				_, err = fd.WriteString(fmt.Sprintf("%d\n", i))
				if err != nil {
					t.Fatalf("could not write test file : %s", err)
					os.Remove("test_files/stream.log")
				}
			}
			fd.Close()
			//we sleep to make sure we detect the new file
			time.Sleep(1 * time.Second)
			os.Remove("test_files/stream.log")
			assert.Equal(t, ts.expectedLines, actualLines)
		}

		if ts.expectedOutput != "" {
			if hook.LastEntry() == nil {
				t.Fatalf("expected output %s, but got nothing", ts.expectedOutput)
			}
			assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
			hook.Reset()
		}

		if ts.teardown != nil {
			ts.teardown()
		}

		tomb.Kill(nil)
	}
}

func TestExclusion(t *testing.T) {

	config := `filenames: ["test_files/*.log*"]
exclude_regexps: ["\\.gz$"]`
	logger, hook := test.NewNullLogger()
	//logger.SetLevel(ts.logLevel)
	subLogger := logger.WithFields(log.Fields{
		"type": "file",
	})
	f := FileSource{}
	err := f.Configure([]byte(config), subLogger)
	if err != nil {
		subLogger.Fatalf("unexpected error: %s", err)
	}
	var expectedLogOutput string
	if runtime.GOOS == "windows" {
		expectedLogOutput = "Skipping file test_files\\test.log.gz as it matches exclude pattern \\.gz"
	} else {
		expectedLogOutput = "Skipping file test_files/test.log.gz as it matches exclude pattern"
	}
	if hook.LastEntry() == nil {
		t.Fatalf("expected output %s, but got nothing", expectedLogOutput)
	}
	assert.Contains(t, hook.LastEntry().Message, expectedLogOutput)
	hook.Reset()
}
