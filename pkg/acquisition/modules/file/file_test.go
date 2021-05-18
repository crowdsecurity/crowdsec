package fileacquisition

import (
	"fmt"
	"os"
	"testing"
	"time"

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
		err := f.ConfigureByDSN(test.dsn, "testtype", subLogger)
		if test.expectedErr != "" {
			assert.Contains(t, err.Error(), test.expectedErr)
		} else {
			assert.Equal(t, err, nil)
		}
	}
}

func TestOneShot(t *testing.T) {
	tests := []struct {
		config         string
		expectedErr    string
		expectedOutput string
		expectedLines  int
		logLevel       log.Level
	}{
		{
			config: `
mode: cat
filename: /etc/shadow`,
			expectedErr:    "failed opening /etc/shadow: open /etc/shadow: permission denied",
			expectedOutput: "",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: cat
filename: /`,
			expectedErr:    "",
			expectedOutput: "/ is a directory, ignoring it",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: cat
filename: "[*-.log"`,
			expectedErr:    "Glob failure: syntax error in pattern",
			expectedOutput: "",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: cat
filename: /do/not/exist`,
			expectedErr:    "",
			expectedOutput: "No matching files for pattern /do/not/exist",
			logLevel:       log.WarnLevel,
			expectedLines:  0,
		},
		{
			config: `
mode: cat
filename: test_files/test.log`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.WarnLevel,
		},
		{
			config: `
mode: cat
filename: test_files/test.log.gz`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  5,
			logLevel:       log.WarnLevel,
		},
		{
			config: `
mode: cat
filename: test_files/bad.gz`,
			expectedErr:    "failed to read gz test_files/bad.gz: unexpected EOF",
			expectedOutput: "",
			expectedLines:  0,
			logLevel:       log.WarnLevel,
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
		err := f.Configure([]byte(ts.config), subLogger)
		if err != nil && ts.expectedErr != "" {
			assert.Contains(t, err.Error(), ts.expectedErr)
			continue
		} else if err != nil && ts.expectedErr == "" {
			t.Fatalf("Unexpected error : %s", err)
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
		if ts.expectedLines != 0 {
			assert.Equal(t, actualLines, ts.expectedLines)
		}
		if ts.expectedErr != "" {
			if err == nil {
				t.Fatalf("Expected error but got nothing ! %+v", ts)
			}
			assert.Contains(t, err.Error(), ts.expectedErr)
		}
		if ts.expectedOutput != "" {
			assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
			hook.Reset()
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
	}{
		{
			config: `
mode: tail
filename: /etc/shadow`,
			expectedErr:    "",
			expectedOutput: "unable to read /etc/shadow : permission denied",
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
		err := f.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
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

		if ts.expectedErr != "" {
			if err == nil {
				t.Fatalf("Expected error but got nothing ! %+v", ts)
			}
			assert.Contains(t, err.Error(), ts.expectedErr)
		}

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
		tomb.Kill(nil)
	}
}
