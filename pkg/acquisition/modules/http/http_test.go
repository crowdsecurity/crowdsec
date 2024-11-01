package httpacquisition

import (
	"compress/gzip"
	"context"
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

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
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
	if h.GetUuid() != "test" {
		t.Fatalf("expected 'test', got '%s'", h.GetUuid())
	}
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
	if h.GetMode() != "test" {
		t.Fatalf("expected 'test', got '%s'", h.GetMode())
	}
}

func TestGetName(t *testing.T) {
	h := HTTPSource{}
	if h.GetName() != "http" {
		t.Fatalf("expected 'http', got '%s'", h.GetName())
	}
}

func SetupAndRunHTTPSource(t *testing.T, h *HTTPSource, config []byte, metricLevel int) (chan types.Event, *tomb.Tomb) {
	ctx := context.Background()
	subLogger := log.WithFields(log.Fields{
		"type": "http",
	})
	err := h.Configure(config, subLogger, metricLevel)
	if err != nil {
		t.Fatalf("unable to configure http source: %s", err)
	}
	tomb := tomb.Tomb{}
	out := make(chan types.Event)
	err = h.StreamingAcquisition(ctx, out, &tomb)
	if err != nil {
		t.Fatalf("unable to start streaming acquisition: %s", err)
	}

	for _, metric := range h.GetMetrics() {
		prometheus.Register(metric)
	}

	return out, &tomb
}

func TestStreamingAcquisitionWrongHTTPMethod(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`), 0)

	time.Sleep(1 * time.Second)

	res, err := http.Get(fmt.Sprintf("%s/test", testHTTPServerAddr))
	if err != nil {
		t.Fatalf("unable to get http response: %s", err)
	}
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected status code %d, got %d", http.StatusMethodNotAllowed, res.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()

}

func TestStreamingAcquisitionUnknownPath(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`), 0)

	time.Sleep(1 * time.Second)

	res, err := http.Get(fmt.Sprintf("%s/unknown", testHTTPServerAddr))
	if err != nil {
		t.Fatalf("unable to get http response: %s", err)
	}

	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status code %d, got %d", http.StatusNotFound, res.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionBasicAuth(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("test"))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.SetBasicAuth("test", "WrongPassword")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionBadHeaders(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test`), 0)

	time.Sleep(1 * time.Second)

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("test"))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "wrong")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionMaxBodySize(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
listen_addr: 127.0.0.1:8080
path: /test
auth_type: headers
headers:
  key: test
max_body_size: 5`), 0)

	time.Sleep(1 * time.Second)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("testtest"))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status code %d, got %d", http.StatusRequestEntityTooLarge, resp.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionSuccess(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 1)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionCustomStatusCodeAndCustomHeaders(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status code %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	if resp.Header.Get("Success") != "true" {
		t.Fatalf("expected header 'success' to be 'true', got '%s'", resp.Header.Get("Success"))
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 1)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
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
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), slow)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Add("Key", "test")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionTLSHTTPRequest(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionTLSWithHeadersAuthSuccess(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	if err != nil {
		t.Fatalf("unable to read ca cert: %s", err)
	}
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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddrTLS), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 0)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionMTLS(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	if err != nil {
		t.Fatalf("unable to load client cert: %s", err)
	}

	caCert, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		t.Fatalf("unable to read ca cert: %s", err)
	}

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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddrTLS), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 0)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionGzipData(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	if _, err := gz.Write([]byte(rawEvt)); err != nil {
		t.Fatalf("unable to write gzipped data: %s", err)
	}
	if _, err := gz.Write([]byte(rawEvt)); err != nil {
		t.Fatalf("unable to write gzipped data: %s", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("unable to close gzip writer: %s", err)
	}

	// send gzipped compressed data
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("Key", "test")
	req.Header.Add("Content-Encoding", "gzip")
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 2)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionNDJson(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
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
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(fmt.Sprintf("%s\n%s\n", rawEvt, rawEvt)))

	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}

	req.Header.Add("Key", "test")
	req.Header.Add("Content-Type", "application/x-ndjson")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	err = <-errChan
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	assertMetrics(t, h.GetMetrics(), 2)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func assertMetrics(t *testing.T, metrics []prometheus.Collector, expected int) {
	promMetrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("unable to gather metrics: %s", err)
	}
	isExist := false
	for _, metricFamily := range promMetrics {
		if metricFamily.GetName() == "cs_httpsource_hits_total" {
			isExist = true
			if len(metricFamily.GetMetric()) != 1 {
				t.Fatalf("expected 1 metricFamily, got %d", len(metricFamily.GetMetric()))
			}
			for _, metric := range metricFamily.GetMetric() {
				if metric.GetCounter().GetValue() != float64(expected) {
					t.Fatalf("expected %d, got %f", expected, metric.GetCounter().GetValue())
				}
				labels := metric.GetLabel()
				if len(labels) != 2 {
					t.Fatalf("expected 2 label, got %d", len(labels))
				}
				if labels[0].GetName() != "path" || labels[0].GetValue() != "/test" {
					t.Fatalf("expected label path:/test, got %s:%s", labels[0].GetName(), labels[0].GetValue())
				}
				if labels[1].GetName() != "src" || labels[1].GetValue() != "127.0.0.1" {
					t.Fatalf("expected label src:127.0.0.1, got %s:%s", labels[1].GetName(), labels[1].GetValue())
				}
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