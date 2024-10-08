//go:build windows

package wineventlogacquisition

import (
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/tomb.v2"
)

func TestBadConfiguration(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}

	exprhelpers.Init(nil)

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

	subLogger := log.WithField("type", "windowseventlog")
	for _, test := range tests {
		f := WinEventLogSource{}
		err := f.Configure([]byte(test.config), subLogger, configuration.METRICS_NONE)
		assert.Contains(t, err.Error(), test.expectedErr)
	}
}

func TestQueryBuilder(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}

	exprhelpers.Init(nil)

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
	subLogger := log.WithField("type", "windowseventlog")
	for _, test := range tests {
		f := WinEventLogSource{}
		f.Configure([]byte(test.config), subLogger, configuration.METRICS_NONE)
		q, err := f.buildXpathQuery()
		if test.expectedErr != "" {
			if err == nil {
				t.Fatalf("expected error '%s' but got none", test.expectedErr)
			}
			assert.Contains(t, err.Error(), test.expectedErr)
		} else {
			require.NoError(t, err)
			assert.Equal(t, test.expectedQuery, q)
		}
	}
}

func TestLiveAcquisition(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}

	exprhelpers.Init(nil)

	tests := []struct {
		config        string
		expectedLines []string
	}{
		{
			config: `source: wineventlog
xpath_query: |
 <QueryList>
   <Query Id="0" Path="Application">
     <Select Path="Application">*[System[(Level=4 or Level=0) and (EventID=42)]]</Select>
   </Query>
 </QueryList>`,
			expectedLines: []string{
				"blabla",
				"test",
				"aaaa",
				"bbbbb",
			},
		},
		{
			config: `source: wineventlog
xpath_query: |
 <sdf>asdfsdf`,
			expectedLines: nil,
		},
		{
			config: `source: wineventlog
event_channel: Application
event_level: Information
event_ids:
 - 42`,
			expectedLines: []string{
				"testmessage",
			},
		},
		{
			config: `source: wineventlog
event_channel: Application
event_level: Information
event_ids:
 - 43`,
			expectedLines: nil,
		},
	}
	subLogger := log.WithField("type", "windowseventlog")

	evthandler, err := eventlog.Open("Application")

	if err != nil {
		t.Fatalf("failed to open event log: %s", err)
	}

	for _, test := range tests {
		to := &tomb.Tomb{}
		c := make(chan types.Event)
		f := WinEventLogSource{}
		f.Configure([]byte(test.config), subLogger, configuration.METRICS_NONE)
		f.StreamingAcquisition(c, to)
		time.Sleep(time.Second)
		lines := test.expectedLines
		go func() {
			for _, line := range lines {
				evthandler.Info(42, line)
			}
		}()
		ticker := time.NewTicker(time.Second * 5)
		linesRead := make([]string, 0)
	READLOOP:
		for {
			select {
			case <-ticker.C:
				if test.expectedLines == nil {
					break READLOOP
				}
				t.Fatalf("timeout")
			case e := <-c:
				line, _ := exprhelpers.XMLGetNodeValue(e.Line.Raw, "/Event/EventData[1]/Data")
				linesRead = append(linesRead, line.(string))
				if len(linesRead) == len(lines) {
					break READLOOP
				}
			}
		}
		if test.expectedLines == nil {
			assert.Empty(t, linesRead)
		} else {
			assert.Equal(t, test.expectedLines, linesRead)
		}
		to.Kill(nil)
		to.Wait()
	}
}

func TestOneShotAcquisition(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping test on non-windows OS")
	}

	tests := []struct {
		name          string
		dsn           string
		expectedCount int
		expectedErr   string
	}{
		{
			name:          "non-existing file",
			dsn:           `wineventlog://foo.evtx`,
			expectedCount: 0,
			expectedErr:   "The system cannot find the file specified.",
		},
		{
			name:          "existing file",
			dsn:           `wineventlog://test_files/Setup.evtx`,
			expectedCount: 24,
			expectedErr:   "",
		},
	}

	exprhelpers.Init(nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lineCount := 0
			to := &tomb.Tomb{}
			c := make(chan types.Event)
			f := WinEventLogSource{}
			f.ConfigureByDSN(test.dsn, map[string]string{"type": "wineventlog"}, log.WithField("type", "windowseventlog"), "")

			go func() {
				for {
					select {
					case <-c:
						lineCount++
					case <-to.Dying():
						return
					}
				}
			}()

			err := f.OneShotAcquisition(c, to)
			if test.expectedErr != "" {
				assert.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.NoError(t, err)

				time.Sleep(2 * time.Second)
				assert.Equal(t, test.expectedCount, lineCount)
			}
		})
	}
}
