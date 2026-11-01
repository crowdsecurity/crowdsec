package victorialogs_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestConfigureDSN(t *testing.T) {
	log.Infof("Test 'TestConfigureDSN'")

	ctx := t.Context()

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
			"type": victorialogs.ModuleName,
			"name": test.name,
		})

		t.Logf("Test : %s", test.name)

		vlSource := &victorialogs.Source{}
		err := vlSource.ConfigureByDSN(ctx, test.dsn, map[string]string{"type": "testtype"}, subLogger, "")
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
			url, err := url.Parse(vlSource.Config.URL)
			require.NoError(t, err)
			require.NotNil(t, url)
			require.Equal(t, test.scheme, url.Scheme)
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
	cstest.SetAWSTestEnv(t)

	ctx := t.Context()

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
		subLogger := logger.WithField("type", victorialogs.ModuleName)
		vlSource := victorialogs.Source{}

		err := vlSource.Configure(ctx, []byte(ts.config), subLogger, metrics.AcquisitionMetricsLevelNone)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		err = feedVLogs(ctx, subLogger, 20, key)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}

		out := make(chan pipeline.Event)
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
	cstest.SetAWSTestEnv(t)

	ctx := t.Context()

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
			streamErr:     `tail request`,
			expectedLines: 0,
		},
		{
			name: "ok",
			config: fmt.Sprintf(`mode: tail
source: victorialogs
url: "http://127.0.0.1:9428"
query: >
  server:"demo" key:%q`, title),
			expectedErr:   "",
			streamErr:     "",
			expectedLines: 20,
		},
	}

	for _, ts := range tests {
		t.Run(ts.name, func(t *testing.T) {
			logger := log.New()
			subLogger := logger.WithFields(log.Fields{
				"type": victorialogs.ModuleName,
				"name": ts.name,
			})

			out := make(chan pipeline.Event)
			vlSource := victorialogs.Source{}

			err := vlSource.Configure(ctx, []byte(ts.config), subLogger, metrics.AcquisitionMetricsLevelNone)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}

			if ts.streamErr != "" {
				err = vlSource.Stream(ctx, out)
				cstest.RequireErrorContains(t, err, ts.streamErr)

				return
			}

			streamCtx, streamCancel := context.WithCancel(ctx)
			streamErr := make(chan error, 1)

			go func() {
				streamErr <- vlSource.Stream(streamCtx, out)
			}()

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

			streamCancel()
			require.NoError(t, <-streamErr)
		})
	}
}

func TestStopStreaming(t *testing.T) {
	cstest.SetAWSTestEnv(t)

	ctx := t.Context()

	config := `
mode: tail
source: victorialogs
url: http://127.0.0.1:9428
query: >
  server:"demo"
`
	logger := log.New()
	subLogger := logger.WithField("type", victorialogs.ModuleName)
	title := time.Now().String()
	vlSource := victorialogs.Source{}

	err := vlSource.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	out := make(chan pipeline.Event, 10)

	streamCtx, streamCancel := context.WithCancel(ctx)
	streamErr := make(chan error, 1)

	go func() {
		streamErr <- vlSource.Stream(streamCtx, out)
	}()

	time.Sleep(time.Second * 2)

	err = feedVLogs(ctx, subLogger, 1, title)
	if err != nil {
		t.Fatalf("Unexpected error : %s", err)
	}

	streamCancel()
	require.NoError(t, <-streamErr)
}

func TestStreamReturnsWhenServerCloses(t *testing.T) {
	ctx := t.Context()

	var conns atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := conns.Add(1)
		fmt.Fprintf(w, `{"_msg":"line %d","_time":%q}`+"\n", n, time.Now().Format(time.RFC3339Nano))

		if n == 1 {
			// the server goes away, e.g. VictoriaLogs restarts
			return
		}

		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	vlSource := victorialogs.Source{}
	config := fmt.Sprintf("mode: tail\nsource: victorialogs\nurl: %s\nquery: '*'\n", srv.URL)
	err := vlSource.Configure(ctx, []byte(config), log.WithField("type", victorialogs.ModuleName), metrics.AcquisitionMetricsLevelNone)
	require.NoError(t, err)

	out := make(chan pipeline.Event, 10)

	err = vlSource.Stream(ctx, out)
	require.ErrorContains(t, err, "tail stream closed by server")
	require.Equal(t, "line 1", (<-out).Line.Raw)

	// the orchestrator calls Stream again
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel() // before srv.Close(), which waits for the handler
	streamErr := make(chan error, 1)

	go func() {
		streamErr <- vlSource.Stream(streamCtx, out)
	}()

	select {
	case evt := <-out:
		require.Equal(t, "line 2", evt.Line.Raw)
	case <-time.After(5 * time.Second):
		t.Fatal("no line after reconnect")
	}

	streamCancel()
	require.NoError(t, <-streamErr)
}

func TestTailModeIgnoredOptionsWarning(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		expectedWarn []string
	}{
		{
			name:   "tail mode, defaults",
			config: "mode: tail",
		},
		{
			name:         "tail mode, wait_for_ready",
			config:       "mode: tail\nwait_for_ready: 5s",
			expectedWarn: []string{"wait_for_ready is ignored in tail mode"},
		},
		{
			name:         "default mode, max_failure_duration",
			config:       "max_failure_duration: 1m",
			expectedWarn: []string{"max_failure_duration is ignored in tail mode"},
		},
		{
			name:   "cat mode, both",
			config: "mode: cat\nwait_for_ready: 5s\nmax_failure_duration: 1m",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			vlSource := victorialogs.Source{}

			config := "source: victorialogs\nurl: http://127.0.0.1:9428\nquery: '*'\n" + tc.config
			err := vlSource.Configure(t.Context(), []byte(config), logger.WithField("type", victorialogs.ModuleName), metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			var warnings []string

			for _, entry := range hook.AllEntries() {
				if entry.Level == log.WarnLevel {
					warnings = append(warnings, entry.Message)
				}
			}

			require.Equal(t, tc.expectedWarn, warnings)
		})
	}
}
