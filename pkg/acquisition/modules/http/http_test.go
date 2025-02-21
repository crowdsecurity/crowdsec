package httpacquisition

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	testHTTPServerAddr    = "http://127.0.0.1:8080"
	testHTTPServerAddrTLS = "https://127.0.0.1:8080"
)

func TestConfigure(t *testing.T) {
	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config: `
foobar: bla`,
			expectedErr: "invalid configuration: listen_addr is required",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: wrongpath`,
			expectedErr: "invalid configuration: path must start with /",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth`,
			expectedErr: "invalid configuration: basic_auth is selected, but basic_auth is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers`,
			expectedErr: "invalid configuration: headers is selected, but headers is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: 132`,
			expectedErr: "invalid configuration: basic_auth is selected, but password is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  password: 132`,
			expectedErr: "invalid configuration: basic_auth is selected, but username is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:`,
			expectedErr: "invalid configuration: headers is selected, but headers is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: toto`,
			expectedErr: "invalid configuration: invalid auth_type: must be one of basic_auth, headers, mtls",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: value
tls:
  server_key: key`,
			expectedErr: "invalid configuration: server_cert is required",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: value
tls:
  server_cert: cert`,
			expectedErr: "invalid configuration: server_key is required",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: mtls
tls:
  server_cert: cert
  server_key: key`,
			expectedErr: "invalid configuration: mtls is selected, but ca_cert is not provided",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: value
max_body_size: 0`,
			expectedErr: "invalid configuration: max_body_size must be positive",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: value
timeout: toto`,
			expectedErr: "cannot parse http datasource configuration: yaml: unmarshal errors:\n  line 8: cannot unmarshal !!str `toto` into time.Duration",
		},
		{
			config: `
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: value
custom_status_code: 999`,
			expectedErr: "invalid configuration: invalid HTTP status code",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "http",
	})

	for _, test := range tests {
		h := HTTPSource{}
		err := h.Configure([]byte(test.config), subLogger, 0)
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestGetUuid(t *testing.T) {
	h := HTTPSource{}
	h.Config.UniqueId = "test"
	assert.Equal(t, "test", h.GetUuid())
}

func TestUnmarshalConfig(t *testing.T) {
	h := HTTPSource{}
	err := h.UnmarshalConfig([]byte(`
source: http
listen_addr: 127.0.0.1:8080
path: 15
	auth_type: headers`))
	cstest.AssertErrorMessage(t, err, "cannot parse http datasource configuration: yaml: line 4: found a tab character that violates indentation")
}

func TestConfigureByDSN(t *testing.T) {
	h := HTTPSource{}
	err := h.ConfigureByDSN("http://localhost:8080/test", map[string]string{}, log.WithFields(log.Fields{
		"type": "http",
	}), "test")
	cstest.AssertErrorMessage(
		t,
		err,
		"http datasource does not support command-line acquisition",
	)
}

func TestGetMode(t *testing.T) {
	h := HTTPSource{}
	h.Config.Mode = "test"
	assert.Equal(t, "test", h.GetMode())
}

func TestGetName(t *testing.T) {
	h := HTTPSource{}
	assert.Equal(t, "http", h.GetName())
}

func SetupAndRunHTTPSource(t *testing.T, h *HTTPSource, config []byte, metricLevel int) (chan types.Event, *prometheus.Registry, *tomb.Tomb) {
	ctx := t.Context()
	subLogger := log.WithFields(log.Fields{
		"type": "http",
	})
	err := h.Configure(config, subLogger, metricLevel)
	require.NoError(t, err)

	tomb := tomb.Tomb{}
	out := make(chan types.Event)
	err = h.StreamingAcquisition(ctx, out, &tomb)
	require.NoError(t, err)

	testRegistry := prometheus.NewPedanticRegistry()
	for _, metric := range h.GetMetrics() {
		err = testRegistry.Register(metric)
		require.NoError(t, err)
	}

	return out, testRegistry, &tomb
}

func TestStreamingAcquisitionWrongHTTPMethod(t *testing.T) {
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`), 0)

	time.Sleep(1 * time.Second)

	res, err := http.Get(fmt.Sprintf("%s/test", testHTTPServerAddr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, res.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionUnknownPath(t *testing.T) {
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`), 0)

	time.Sleep(1 * time.Second)

	res, err := http.Get(fmt.Sprintf("%s/unknown", testHTTPServerAddr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionBasicAuth(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`), 0)

	time.Sleep(1 * time.Second)

	client := &http.Client{}

	resp, err := http.Post(fmt.Sprintf("%s/test", testHTTPServerAddr), "application/json", strings.NewReader("test"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("test"))
	require.NoError(t, err)
	req.SetBasicAuth("test", "WrongPassword")

	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionBadHeaders(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test`), 0)

	time.Sleep(1 * time.Second)

	client := &http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("test"))
	require.NoError(t, err)

	req.Header.Add("Key", "wrong")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionMaxBodySize(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test
max_body_size: 5`), 0)

	time.Sleep(1 * time.Second)

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("testtest"))
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionSuccess(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test`), 2)

	time.Sleep(1 * time.Second)

	rawEvt := `{"test": "test"}`

	errChan := make(chan error)
	go assertEvents(out, []string{rawEvt}, errChan)

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 1)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionCustomStatusCodeAndCustomHeaders(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test
custom_status_code: 201
custom_headers:
  success: true`), 2)

	time.Sleep(1 * time.Second)

	rawEvt := `{"test": "test"}`
	errChan := make(chan error)

	go assertEvents(out, []string{rawEvt}, errChan)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "true", resp.Header.Get("Success"))

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 1)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

type slowReader struct {
	delay time.Duration
	body  []byte
	index int
}

func (sr *slowReader) Read(p []byte) (int, error) {
	if sr.index >= len(sr.body) {
		return 0, io.EOF
	}

	time.Sleep(sr.delay) // Simulate a delay in reading
	n := copy(p, sr.body[sr.index:])
	sr.index += n

	return n, nil
}

func assertEvents(out chan types.Event, expected []string, errChan chan error) {
	readLines := []types.Event{}

	for i := 0; i < len(expected); i++ {
		select {
		case event := <-out:
			readLines = append(readLines, event)
		case <-time.After(2 * time.Second):
			errChan <- errors.New("timeout waiting for event")
			return
		}
	}

	if len(readLines) != len(expected) {
		errChan <- fmt.Errorf("expected %d lines, got %d", len(expected), len(readLines))
		return
	}

	for i, evt := range readLines {
		if evt.Line.Raw != expected[i] {
			errChan <- fmt.Errorf(`expected %s, got '%+v'`, expected, evt.Line.Raw)
			return
		}

		if evt.Line.Src != "127.0.0.1" {
			errChan <- fmt.Errorf("expected '127.0.0.1', got '%s'", evt.Line.Src)
			return
		}

		if evt.Line.Module != "http" {
			errChan <- fmt.Errorf("expected 'http', got '%s'", evt.Line.Module)
			return
		}
	}
	errChan <- nil
}

func TestStreamingAcquisitionTimeout(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test
timeout: 1s`), 0)

	time.Sleep(1 * time.Second)

	slow := &slowReader{
		delay: 2 * time.Second,
		body:  []byte(`{"test": "delayed_payload"}`),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), slow)
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionTLSHTTPRequest(t *testing.T) {
	h := &HTTPSource{}
	_, _, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
auth_type: mtls
path: /test
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
  ca_cert: testdata/ca.crt`), 0)

	time.Sleep(1 * time.Second)

	resp, err := http.Post(fmt.Sprintf("%s/test", testHTTPServerAddr), "application/json", strings.NewReader("test"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionTLSWithHeadersAuthSuccess(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
`), 0)

	time.Sleep(1 * time.Second)

	caCert, err := os.ReadFile("testdata/server.crt")
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	rawEvt := `{"test": "test"}`
	errChan := make(chan error)

	go assertEvents(out, []string{rawEvt}, errChan)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddrTLS), strings.NewReader(rawEvt))
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 0)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionMTLS(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: mtls
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
  ca_cert: testdata/ca.crt`), 0)

	time.Sleep(1 * time.Second)

	// init client cert
	cert, err := tls.LoadX509KeyPair("testdata/client.crt", "testdata/client.key")
	require.NoError(t, err)

	caCert, err := os.ReadFile("testdata/ca.crt")
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	rawEvt := `{"test": "test"}`
	errChan := make(chan error)

	go assertEvents(out, []string{rawEvt}, errChan)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddrTLS), strings.NewReader(rawEvt))
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 0)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionGzipData(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test`), 2)

	time.Sleep(1 * time.Second)

	rawEvt := `{"test": "test"}`
	errChan := make(chan error)

	go assertEvents(out, []string{rawEvt, rawEvt}, errChan)

	var b strings.Builder
	gz := gzip.NewWriter(&b)

	_, err := gz.Write([]byte(rawEvt))
	require.NoError(t, err)

	_, err = gz.Write([]byte(rawEvt))
	require.NoError(t, err)

	err = gz.Close()
	require.NoError(t, err)

	// send gzipped compressed data
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(b.String()))
	require.NoError(t, err)

	req.Header.Add("Key", "test")
	req.Header.Add("Content-Encoding", "gzip")
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 2)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func TestStreamingAcquisitionNDJson(t *testing.T) {
	ctx := t.Context()
	h := &HTTPSource{}
	out, reg, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test`), 2)

	time.Sleep(1 * time.Second)

	rawEvt := `{"test": "test"}`
	errChan := make(chan error)

	go assertEvents(out, []string{rawEvt, rawEvt}, errChan)

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(fmt.Sprintf("%s\n%s\n", rawEvt, rawEvt)))

	require.NoError(t, err)

	req.Header.Add("Key", "test")
	req.Header.Add("Content-Type", "application/x-ndjson")

	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = <-errChan
	require.NoError(t, err)

	assertMetrics(t, reg, h.GetMetrics(), 2)

	h.Server.Close()
	tomb.Kill(nil)
	err = tomb.Wait()
	require.NoError(t, err)
}

func assertMetrics(t *testing.T, reg *prometheus.Registry, metrics []prometheus.Collector, expected int) {
	promMetrics, err := reg.Gather()
	require.NoError(t, err)

	isExist := false

	for _, metricFamily := range promMetrics {
		if metricFamily.GetName() == "cs_httpsource_hits_total" {
			isExist = true

			assert.Len(t, metricFamily.GetMetric(), 1)

			for _, metric := range metricFamily.GetMetric() {
				assert.InDelta(t, float64(expected), metric.GetCounter().GetValue(), 0.000001)
				labels := metric.GetLabel()
				assert.Len(t, labels, 2)
				assert.Equal(t, "path", labels[0].GetName())
				assert.Equal(t, "/test", labels[0].GetValue())
				assert.Equal(t, "src", labels[1].GetName())
				assert.Equal(t, "127.0.0.1", labels[1].GetValue())
			}
		}
	}

	if !isExist && expected > 0 {
		t.Fatalf("expected metric cs_httpsource_hits_total not found")
	}

	for _, metric := range metrics {
		metric.(*prometheus.CounterVec).Reset()
	}
}
