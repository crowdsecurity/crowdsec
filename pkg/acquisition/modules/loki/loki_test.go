package loki_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"
	"gotest.tools/v3/assert"
)

func TestConfiguration(t *testing.T) {

	log.Infof("Test 'TestConfigure'")

	tests := []struct {
		config       string
		expectedErr  string
		password     string
		waitForReady time.Duration
		delayFor     time.Duration
		testName     string
	}{
		{
			config:      `foobar: asd`,
			expectedErr: "line 1: field foobar not found in type loki.LokiConfiguration",
			testName:    "Unknown field",
		},
		{
			config: `
mode: tail
source: loki`,
			expectedErr: "loki query is mandatory",
			testName:    "Missing url",
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
`,
			expectedErr: "loki query is mandatory",
			testName:    "Missing query",
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
query: >
        {server="demo"}
`,
			expectedErr: "",
			testName:    "Correct config",
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
wait_for_ready: 5s
query: >
        {server="demo"}
`,
			expectedErr:  "",
			testName:     "Correct config with wait_for_ready",
			waitForReady: 5 * time.Second,
		},
		{
			config: `
mode: tail
source: loki
url: http://localhost:3100/
delay_for: 1s
query: >
        {server="demo"}
`,
			expectedErr: "",
			testName:    "Correct config with delay_for",
			delayFor:    1 * time.Second,
		},
		{

			config: `
mode: tail
source: loki
url: http://localhost:3100/
auth:
  username: foo
  password: bar
query: >
        {server="demo"}
`,
			expectedErr: "",
			password:    "bar",
			testName:    "Correct config with password",
		},
		{

			config: `
mode: tail
source: loki
url: http://localhost:3100/
delay_for: 10s
query: >
        {server="demo"}
`,
			expectedErr: "delay_for should be a value between 1s and 5s",
			testName:    "Invalid DelayFor",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "loki",
	})
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			lokiSource := loki.LokiSource{}
			err := lokiSource.Configure([]byte(test.config), subLogger)
			cstest.AssertErrorContains(t, err, test.expectedErr)
			if test.password != "" {
				p := lokiSource.Config.Auth.Password
				if test.password != p {
					t.Fatalf("Password mismatch : %s != %s", test.password, p)
				}
			}
			if test.waitForReady != 0 {
				if lokiSource.Config.WaitForReady != test.waitForReady {
					t.Fatalf("Wrong WaitForReady %v != %v", lokiSource.Config.WaitForReady, test.waitForReady)
				}
			}
			if test.delayFor != 0 {
				if lokiSource.Config.DelayFor != test.delayFor {
					t.Fatalf("Wrong DelayFor %v != %v", lokiSource.Config.DelayFor, test.delayFor)
				}
			}
		})
	}
}

func TestConfigureDSN(t *testing.T) {
	log.Infof("Test 'TestConfigureDSN'")
	tests := []struct {
		name         string
		dsn          string
		expectedErr  string
		since        time.Time
		password     string
		scheme       string
		waitForReady time.Duration
		delayFor     time.Duration
	}{
		{
			name:        "Wrong scheme",
			dsn:         "wrong://",
			expectedErr: "invalid DSN wrong:// for loki source, must start with loki://",
		},
		{
			name:        "Correct DSN",
			dsn:         `loki://localhost:3100/?query={server="demo"}`,
			expectedErr: "",
		},
		{
			name:        "Empty host",
			dsn:         "loki://",
			expectedErr: "empty loki host",
		},
		{
			name:        "Invalid DSN",
			dsn:         "loki",
			expectedErr: "invalid DSN loki for loki source, must start with loki://",
		},
		{
			name:        "Invalid Delay",
			dsn:         `loki://localhost:3100/?query={server="demo"}&delay_for=10s`,
			expectedErr: "delay_for should be a value between 1s and 5s",
		},
		{
			name:  "Bad since param",
			dsn:   `loki://127.0.0.1:3100/?since=3h&query={server="demo"}`,
			since: time.Now().Add(-3 * time.Hour),
		},
		{
			name:     "Basic Auth",
			dsn:      `loki://login:password@localhost:3102/?query={server="demo"}`,
			password: "password",
		},
		{
			name:         "Correct DSN",
			dsn:          `loki://localhost:3100/?query={server="demo"}&wait_for_ready=5s&delay_for=1s`,
			expectedErr:  "",
			waitForReady: 5 * time.Second,
			delayFor:     1 * time.Second,
		},
		{
			name:   "SSL DSN",
			dsn:    `loki://localhost:3100/?ssl=true`,
			scheme: "https",
		},
	}

	for _, test := range tests {
		subLogger := log.WithFields(log.Fields{
			"type": "loki",
			"name": test.name,
		})
		t.Logf("Test : %s", test.name)
		lokiSource := &loki.LokiSource{}
		err := lokiSource.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger, "")
		cstest.AssertErrorContains(t, err, test.expectedErr)

		noDuration, _ := time.ParseDuration("0s")
		if lokiSource.Config.Since != noDuration && lokiSource.Config.Since.Round(time.Second) != time.Since(test.since).Round(time.Second) {
			t.Fatalf("Invalid since %v", lokiSource.Config.Since)
		}

		if test.password != "" {
			p := lokiSource.Config.Auth.Password
			if test.password != p {
				t.Fatalf("Password mismatch : %s != %s", test.password, p)
			}
		}
		if test.scheme != "" {
			url, _ := url.Parse(lokiSource.Config.URL)
			if test.scheme != url.Scheme {
				t.Fatalf("Schema mismatch : %s != %s", test.scheme, url.Scheme)
			}
		}
		if test.waitForReady != 0 {
			if lokiSource.Config.WaitForReady != test.waitForReady {
				t.Fatalf("Wrong WaitForReady %v != %v", lokiSource.Config.WaitForReady, test.waitForReady)
			}
		}
		if test.delayFor != 0 {
			if lokiSource.Config.DelayFor != test.delayFor {
				t.Fatalf("Wrong DelayFor %v != %v", lokiSource.Config.DelayFor, test.delayFor)
			}
		}
	}
}

func feedLoki(logger *log.Entry, n int, title string) error {
	streams := LogStreams{
		Streams: []LogStream{
			{
				Stream: map[string]string{
					"server": "demo",
					"domain": "cw.example.com",
					"key":    title,
				},
				Values: make([]LogValue, n),
			},
		},
	}
	for i := 0; i < n; i++ {
		streams.Streams[0].Values[i] = LogValue{
			Time: time.Now(),
			Line: fmt.Sprintf("Log line #%d %v", i, title),
		}
	}
	buff, err := json.Marshal(streams)
	if err != nil {
		return err
	}
	resp, err := http.Post("http://127.0.0.1:3100/loki/api/v1/push", "application/json", bytes.NewBuffer(buff))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		logger.Error(string(b))
		return fmt.Errorf("Bad post status %d", resp.StatusCode)
	}
	logger.Info(n, " Events sent")
	return nil
}

func TestOneShotAcquisition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.Info("Test 'TestStreamingAcquisition'")
	title := time.Now().String() // Loki will be messy, with a lot of stuff, lets use a unique key
	tests := []struct {
		config string
	}{
		{
			config: fmt.Sprintf(`
mode: cat
source: loki
url: http://127.0.0.1:3100
query: '{server="demo",key="%s"}'
since: 1h
`, title),
		},
	}

	for _, ts := range tests {
		logger := log.New()
		subLogger := logger.WithFields(log.Fields{
			"type": "loki",
		})
		lokiSource := loki.LokiSource{}
		err := lokiSource.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		err = feedLoki(subLogger, 20, title)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		out := make(chan types.Event)
		read := 0
		go func() {
			for {
				<-out
				read++
			}
		}()
		lokiTomb := tomb.Tomb{}
		err = lokiSource.OneShotAcquisition(out, &lokiTomb)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		assert.Equal(t, 20, read)

	}
}

func TestStreamingAcquisition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.Info("Test 'TestStreamingAcquisition'")
	title := time.Now().String()
	tests := []struct {
		name          string
		config        string
		expectedErr   string
		streamErr     string
		expectedLines int
	}{
		{
			name: "Bad port",
			config: `
mode: tail
source: loki
url: http://127.0.0.1:3101
query: >
  {server="demo"}
`, // No Loki server here
			expectedErr:   "",
			streamErr:     `loki is not ready: context deadline exceeded`,
			expectedLines: 0,
		},
		{
			name: "ok",
			config: `
mode: tail
source: loki
url: http://127.0.0.1:3100
query: >
  {server="demo"}
`,
			expectedErr:   "",
			streamErr:     "",
			expectedLines: 20,
		},
	}
	for _, ts := range tests {
		t.Run(ts.name, func(t *testing.T) {
			logger := log.New()
			subLogger := logger.WithFields(log.Fields{
				"type": "loki",
				"name": ts.name,
			})

			out := make(chan types.Event)
			lokiTomb := tomb.Tomb{}
			lokiSource := loki.LokiSource{}
			err := lokiSource.Configure([]byte(ts.config), subLogger)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}
			err = lokiSource.StreamingAcquisition(out, &lokiTomb)
			cstest.AssertErrorContains(t, err, ts.streamErr)

			if ts.streamErr != "" {
				return
			}

			time.Sleep(time.Second * 2) //We need to give time to start reading from the WS
			readTomb := tomb.Tomb{}
			readCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			count := 0

			readTomb.Go(func() error {
				defer cancel()
				for {
					select {
					case <-readCtx.Done():
						return readCtx.Err()
					case evt := <-out:
						count++
						if !strings.HasSuffix(evt.Line.Raw, title) {
							return fmt.Errorf("Incorrect suffix : %s", evt.Line.Raw)
						}
						if count == ts.expectedLines {
							return nil
						}
					}
				}
			})

			err = feedLoki(subLogger, ts.expectedLines, title)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}

			err = readTomb.Wait()
			cancel()
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}
			assert.Equal(t, count, ts.expectedLines)
		})
	}

}

func TestStopStreaming(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}
	config := `
mode: tail
source: loki
url: http://127.0.0.1:3100
query: >
  {server="demo"}
`
	logger := log.New()
	subLogger := logger.WithFields(log.Fields{
		"type": "loki",
	})
	title := time.Now().String()
	lokiSource := loki.LokiSource{}
	err := lokiSource.Configure([]byte(config), subLogger)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}
	out := make(chan types.Event)

	lokiTomb := &tomb.Tomb{}
	err = lokiSource.StreamingAcquisition(out, lokiTomb)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}
	time.Sleep(time.Second * 2)
	err = feedLoki(subLogger, 1, title)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	lokiTomb.Kill(nil)
	err = lokiTomb.Wait()
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}
}

type LogStreams struct {
	Streams []LogStream `json:"streams"`
}

type LogStream struct {
	Stream map[string]string `json:"stream"`
	Values []LogValue        `json:"values"`
}

type LogValue struct {
	Time time.Time
	Line string
}

func (l *LogValue) MarshalJSON() ([]byte, error) {
	line, err := json.Marshal(l.Line)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`["%d",%s]`, l.Time.UnixNano(), string(line))), nil
}
