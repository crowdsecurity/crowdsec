package file_acquisition

import (
	"os"
	"testing"

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
			expectedErr: "line 1: field foobar not found in type file_acquisition.FileConfiguration",
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
			dsn:         "file:///etc/passwd",
			expectedErr: "",
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
	}{
		{
			config: `
mode: cat
filename: /etc/shadow`,
			expectedErr:    "failed opening /etc/shadow: open /etc/shadow: permission denied",
			expectedOutput: "",
		},
		{
			config: `
mode: cat
filename: /`,
			expectedErr:    "",
			expectedOutput: "/ is a directory, ignoring it",
		},
	}

	logger, hook := test.NewNullLogger()
	logger.SetLevel(log.WarnLevel)
	subLogger := logger.WithFields(log.Fields{
		"type": "file",
	})
	tomb := tomb.Tomb{}
	out := make(chan types.Event)

	for _, test := range tests {
		f := FileSource{}
		err := f.Configure([]byte(test.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		err = f.OneShotAcquisition(out, &tomb)
		if test.expectedErr != "" {
			assert.Contains(t, err.Error(), test.expectedErr)
		}
		if test.expectedOutput != "" {
			assert.Contains(t, hook.LastEntry().Message, test.expectedOutput)
			continue
		}
	}
}

func TestLiveAcquisition(t *testing.T) {

}

func setup() {

}

func teardown() {

}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}
