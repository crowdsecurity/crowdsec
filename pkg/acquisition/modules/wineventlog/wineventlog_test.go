package wineventlogacquisition

import (
	"runtime"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestBadConfiguration(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config: `source: wineventlog
foobar: 42`,
			expectedErr: "field foobar not found in type wineventlogacquisition.WinEventLogConfiguration",
		},
		{
			config:      `source: wineventlog`,
			expectedErr: "event_channel or xpath_query must be set",
		},
		{
			config: `source: wineventlog
event_channel: Security
event_level: blabla`,
			expectedErr: "buildXpathQuery failed: invalid log level",
		},
		{
			config: `source: wineventlog
event_channel: Security
event_level: blabla`,
			expectedErr: "buildXpathQuery failed: invalid log level",
		},
		{
			config: `source: wineventlog
event_channel: foo
xpath_query: test`,
			expectedErr: "event_channel and xpath_query are mutually exclusive",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "windowseventlog",
	})
	for _, test := range tests {
		f := WinEventLogSource{}
		err := f.Configure([]byte(test.config), subLogger)
		assert.Contains(t, err.Error(), test.expectedErr)
	}
}

func TestQueryBuilder(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}
	tests := []struct {
		config        string
		expectedQuery string
		expectedErr   string
	}{
		{
			config: `source: wineventlog
event_channel: Security
event_level: Information`,
			expectedQuery: "<QueryList><Query><Select Path=\"Security\">*[System[(Level=0 or Level=4)]]</Select></Query></QueryList>",
			expectedErr:   "",
		},
		{
			config: `source: wineventlog
event_channel: Security
event_level: Error
event_ids:
 - 42`,
			expectedQuery: "<QueryList><Query><Select Path=\"Security\">*[System[(EventID=42) and (Level=2)]]</Select></Query></QueryList>",
			expectedErr:   "",
		},
		{
			config: `source: wineventlog
event_channel: Security
event_level: Error
event_ids:
 - 42
 - 43`,
			expectedQuery: "<QueryList><Query><Select Path=\"Security\">*[System[(EventID=42 or EventID=43) and (Level=2)]]</Select></Query></QueryList>",
			expectedErr:   "",
		},
		{
			config: `source: wineventlog
event_channel: Security`,
			expectedQuery: "<QueryList><Query><Select Path=\"Security\">*</Select></Query></QueryList>",
			expectedErr:   "",
		},
		{
			config: `source: wineventlog
event_channel: Security
event_level: bla`,
			expectedQuery: "",
			expectedErr:   "invalid log level",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "windowseventlog",
	})
	for _, test := range tests {
		f := WinEventLogSource{}
		f.Configure([]byte(test.config), subLogger)
		q, err := f.buildXpathQuery()
		if test.expectedErr != "" {
			if err == nil {
				t.Fatalf("expected error '%s' but got none", test.expectedErr)
			}
			assert.Contains(t, err.Error(), test.expectedErr)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expectedQuery, q)
		}
	}
}

func TestLiveAcquisition(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}
}
