package victorialogs_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestConfiguration(t *testing.T) {
	log.Infof("Test 'TestConfigure'")

	tests := []struct {
		config       string
		expectedErr  string
		password     string
		waitForReady time.Duration
		testName     string
	}{
		{
			config:      `foobar: asd`,
			expectedErr: "line 1: field foobar not found in type victorialogs.VLConfiguration",
			testName:    "Unknown field",
		},
		{
			config: `
mode: tail
source: victorialogs`,
			expectedErr: "query is mandatory",
			testName:    "Missing url",
		},
		{
			config: `
mode: tail
source: victorialogs
url: http://localhost:9428/
`,
			expectedErr: "query is mandatory",
			testName:    "Missing query",
		},
		{
			config: `
mode: tail
source: victorialogs
url: http://localhost:9428/
query: >
        {server="demo"}
`,
			expectedErr: "",
			testName:    "Correct config",
		},
		{
			config: `
mode: tail
source: victorialogs
url: http://localhost:9428/
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
source: victorialogs
url: http://localhost:9428/
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
	}
	subLogger := log.WithField("type", "victorialogs")

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			vlSource := victorialogs.VLSource{}
			err := vlSource.Configure([]byte(test.config), subLogger, configuration.METRICS_NONE)
			cstest.AssertErrorContains(t, err, test.expectedErr)

			if test.password != "" {
				p := vlSource.Config.Auth.Password
				if test.password != p {
					t.Fatalf("Password mismatch : %s != %s", test.password, p)
				}
			}

			if test.waitForReady != 0 {
				if vlSource.Config.WaitForReady != test.waitForReady {
					t.Fatalf("Wrong WaitForReady %v != %v", vlSource.Config.WaitForReady, test.waitForReady)
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
	}{
		{
			name:        "Wrong scheme",
			dsn:         "wrong://",
			expectedErr: "invalid DSN wrong:// for VictoriaLogs source, must start with victorialogs://",
		},
		{
			name:        "Correct DSN",
			dsn:         `victorialogs://localhost:9428/?query={server="demo"}`,
			expectedErr: "",
		},
		{
			name:        "Empty host",
			dsn:         "victorialogs://",
			expectedErr: "empty host",
		},
		{
			name:        "Invalid DSN",
			dsn:         "victorialogs",
			expectedErr: "invalid DSN victorialogs for VictoriaLogs source, must start with victorialogs://",
		},
		{
			name:  "Bad since param",
			dsn:   `victorialogs://127.0.0.1:9428/?since=3h&query={server="demo"}`,
			since: time.Now().Add(-3 * time.Hour),
		},
		{
			name:     "Basic Auth",
			dsn:      `victorialogs://login:password@localhost:3102/?query={server="demo"}`,
			password: "password",
		},
		{
			name:         "Correct DSN",
			dsn:          `victorialogs://localhost:9428/?query={server="demo"}&wait_for_ready=5s`,
			expectedErr:  "",
			waitForReady: 5 * time.Second,
		},
		{
			name:   "SSL DSN",
			dsn:    `victorialogs://localhost:9428/?ssl=true`,
			scheme: "https",
		},
	}

	for _, test := range tests {
		subLogger := log.WithFields(log.Fields{
			"type": "victorialogs",
			"name": test.name,
		})

		t.Logf("Test : %s", test.name)

		vlSource := &victorialogs.VLSource{}
		err := vlSource.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger, "")
		cstest.AssertErrorContains(t, err, test.expectedErr)

		noDuration, _ := time.ParseDuration("0s")
		if vlSource.Config.Since != noDuration && vlSource.Config.Since.Round(time.Second) != time.Since(test.since).Round(time.Second) {
			t.Fatalf("Invalid since %v", vlSource.Config.Since)
		}

		if test.password != "" {
			p := vlSource.Config.Auth.Password
			if test.password != p {
				t.Fatalf("Password mismatch : %s != %s", test.password, p)
			}
		}

		if test.scheme != "" {
			url, _ := url.Parse(vlSource.Config.URL)
			if test.scheme != url.Scheme {
				t.Fatalf("Schema mismatch : %s != %s", test.scheme, url.Scheme)
			}
		}

		if test.waitForReady != 0 {
			if vlSource.Config.WaitForReady != test.waitForReady {
				t.Fatalf("Wrong WaitForReady %v != %v", vlSource.Config.WaitForReady, test.waitForReady)
			}
		}
	}
}

// Ingestion format docs: https://docs.victoriametrics.com/victorialogs/data-ingestion/#json-stream-api
func feedVLogs(ctx context.Context, logger *log.Entry, n int, title string) error {
	bb := bytes.NewBuffer(nil)
	for i := range n {
		fmt.Fprintf(bb,
			`{ "_time": %q,"_msg":"Log line #%d %v", "server": "demo", "key": %q}
`, time.Now().Format(time.RFC3339), i, title, title)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:9428/insert/jsonline?_stream_fields=server,key", bb)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		logger.Error(string(b))

		return fmt.Errorf("Bad post status %d", resp.StatusCode)
	}

	logger.Info(n, " Events sent")
	// VictoriaLogs buffers data before saving to disk
	// Default flush deadline is 2s, waiting 3s to be safe
	time.Sleep(3 * time.Second)

	return nil
}

func TestOneShotAcquisition(t *testing.T) {
	ctx := t.Context()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.Info("Test 'TestStreamingAcquisition'")

	key := strconv.Itoa(rand.Intn(1000))
	tests := []struct {
		config string
	}{
		{
			config: fmt.Sprintf(`
mode: cat
source: victorialogs
url: http://127.0.0.1:9428
query: >
  {server=demo, key=%q}
since: 1h
`, key),
		},
	}

	for _, ts := range tests {
		logger := log.New()
		subLogger := logger.WithField("type", "victorialogs")
		vlSource := victorialogs.VLSource{}

		err := vlSource.Configure([]byte(ts.config), subLogger, configuration.METRICS_NONE)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		err = feedVLogs(ctx, subLogger, 20, key)
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

		vlTomb := tomb.Tomb{}

		err = vlSource.OneShotAcquisition(ctx, out, &vlTomb)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		// Some logs might be buffered
		assert.Greater(t, read, 10)
	}
}

func TestStreamingAcquisition(t *testing.T) {
	ctx := t.Context()

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
			config: `mode: tail
source: victorialogs
url: "http://127.0.0.1:9429"
query: >
  server:"demo"`, // Wrong port
			expectedErr:   "",
			streamErr:     `VictoriaLogs is not ready`,
			expectedLines: 0,
		},
		{
			name: "ok",
			config: `mode: tail
source: victorialogs
url: "http://127.0.0.1:9428"
query: >
  server:"demo"`,
			expectedErr:   "",
			streamErr:     "",
			expectedLines: 20,
		},
	}

	for _, ts := range tests {
		t.Run(ts.name, func(t *testing.T) {
			logger := log.New()
			subLogger := logger.WithFields(log.Fields{
				"type": "victorialogs",
				"name": ts.name,
			})

			out := make(chan types.Event)
			vlTomb := tomb.Tomb{}
			vlSource := victorialogs.VLSource{}

			err := vlSource.Configure([]byte(ts.config), subLogger, configuration.METRICS_NONE)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}

			err = vlSource.StreamingAcquisition(ctx, out, &vlTomb)
			cstest.AssertErrorContains(t, err, ts.streamErr)

			if ts.streamErr != "" {
				return
			}

			time.Sleep(time.Second * 2) // We need to give time to start reading from the WS

			readTomb := tomb.Tomb{}
			readCtx, cancel := context.WithTimeout(ctx, time.Second*10)
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

			err = feedVLogs(ctx, subLogger, ts.expectedLines, title)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}

			err = readTomb.Wait()

			cancel()

			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}

			assert.Equal(t, ts.expectedLines, count)
		})
	}
}

func TestStopStreaming(t *testing.T) {
	ctx := t.Context()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on windows")
	}

	config := `
mode: tail
source: victorialogs
url: http://127.0.0.1:9428
query: >
  server:"demo"
`
	logger := log.New()
	subLogger := logger.WithField("type", "victorialogs")
	title := time.Now().String()
	vlSource := victorialogs.VLSource{}

	err := vlSource.Configure([]byte(config), subLogger, configuration.METRICS_NONE)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	out := make(chan types.Event, 10)

	vlTomb := &tomb.Tomb{}

	err = vlSource.StreamingAcquisition(ctx, out, vlTomb)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	time.Sleep(time.Second * 2)

	err = feedVLogs(ctx, subLogger, 1, title)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	vlTomb.Kill(nil)

	err = vlTomb.Wait()
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}
}
