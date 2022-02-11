package fileacquisition

import (
	"fmt"
	"os"
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
			dsn:         "file:///etc/passwd?log_level=warn",
			expectedErr: "",
		},
		{
			dsn:         "file:///etc/passwd?log_level=foobar",
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
			config: `
mode: cat
filename: /etc/shadow`,
			expectedConfigErr: "",
			expectedErr:       "failed opening /etc/shadow: open /etc/shadow: permission denied",
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
				os.Create("test_files/test_delete.log")
			},
			afterConfigure: func() {
				os.Remove("test_files/test_delete.log")
			},
			expectedErr: "could not stat file test_files/test_delete.log : stat test_files/test_delete.log: no such file or directory",
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
	tests := []struct {
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
			config: `
mode: tail
filename: /etc/shadow`,
			expectedErr:    "",
			expectedOutput: "unable to read /etc/shadow : open /etc/shadow: permission denied",
			logLevel:       log.InfoLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: tail
filename: /`,
			expectedErr:    "",
			expectedOutput: "/ is a directory, ignoring it",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: tail
filename: /do/not/exist`,
			expectedErr:    "",
			expectedOutput: "No matching files for pattern /do/not/exist",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: tail
filenames:
 - test_files/*.log
force_inotify: true`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
		},
		{
			config: `
mode: tail
filenames:
 - test_files/*.log
force_inotify: true`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  0,
			logLevel:       log.DebugLevel,
			afterConfigure: func() {
				os.Create("test_files/a.log")
				os.Remove("test_files/a.log")
			},
		},
		{
			config: `
mode: tail
filenames:
 - test_files/*.log
force_inotify: true`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
			afterConfigure: func() {
				os.Create("test_files/a.log")
				time.Sleep(1 * time.Second)
				os.Chmod("test_files/a.log", 0000)
			},
			teardown: func() {
				os.Chmod("test_files/a.log", 0644)
				os.Remove("test_files/a.log")
			},
		},
		{
			config: `
mode: tail
filenames:
 - test_files/*.log
force_inotify: true`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.DebugLevel,
			afterConfigure: func() {
				os.Mkdir("test_files/pouet/", 0700)
			},
			teardown: func() {
				os.Remove("test_files/pouet/")
			},
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
			assert.Equal(t, actualLines, ts.expectedLines)
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
