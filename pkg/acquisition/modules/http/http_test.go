package httpacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/go-cs-lib/cstest"
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
			expectedErr: "invalid configuration: port is required",
		},
		{
			config: `
source: http
port: aa`,
			expectedErr: "cannot parse http datasource configuration: yaml: unmarshal errors:\n  line 3: cannot unmarshal !!str `aa` into int",
		},
		{
			config: `
source: http
port: 8080`,
			expectedErr: "invalid configuration: path is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: basic_auth`,
			expectedErr: "invalid configuration: basic_auth is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: headers`,
			expectedErr: "invalid configuration: headers is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: basic_auth
basic_auth:
  username: 132`,
			expectedErr: "invalid configuration: password is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: basic_auth
basic_auth:
  password: 132`,
			expectedErr: "invalid configuration: username is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: headers
headers:`,
			expectedErr: "invalid configuration: headers is required",
		},
		{
			config: `
source: http
port: 8080
path: /test
auth_type: toto`,
			expectedErr: "invalid configuration: at least one of tls or auth_type is required",
		},
		{
			config: `
source: http
port: 8080
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
port: 8080
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
port: 8080
path: /test
auth_type: mtls
tls:
  server_cert: cert
  server_key: key`,
			expectedErr: "invalid configuration: ca_cert is required",
		},
		{
			config: `
source: http
port: 8080
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
port: 8080
path: /test
auth_type: headers
headers:
  key: value
chunk_size: 0`,
			expectedErr: "invalid configuration: chunk_size must be positive",
		},
		{
			config: `
source: http
port: 8080
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
port: 8080
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
port: 8080
path: 15
	auth_type: headers`))
	cstest.AssertErrorMessage(t, err, "cannot parse http datasource configuration: yaml: line 5: found a tab character that violates indentation")
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

func SetupAndRunHTTPSource(t *testing.T, h *HTTPSource, config []byte) (chan types.Event, *tomb.Tomb) {
	ctx := context.Background()
	subLogger := log.WithFields(log.Fields{
		"type": "http",
	})
	err := h.Configure(config, subLogger, 0)
	if err != nil {
		t.Fatalf("unable to configure http source: %s", err)
	}
	tomb := tomb.Tomb{}
	out := make(chan types.Event)
	err = h.StreamingAcquisition(ctx, out, &tomb)
	if err != nil {
		t.Fatalf("unable to start streaming acquisition: %s", err)
	}
	return out, &tomb
}

func TestStreamingAcquisitionWrongHTTPMethod(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
port: 8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`))

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
port: 8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`))

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
port: 8080
path: /test
auth_type: basic_auth
basic_auth:
  username: test
  password: test`))

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
port: 8080
path: /test
auth_type: headers
headers:
  key: test`))

	time.Sleep(1 * time.Second)

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("test"))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("key", "wrong")
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
port: 8080
path: /test
auth_type: headers
headers:
  key: test
max_body_size: 5`))

	time.Sleep(1 * time.Second)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader("testtest"))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("key", "test")
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
port: 8080
path: /test
auth_type: headers
headers:
  key: test`))

	time.Sleep(1 * time.Second)
	rawEvt := `{"test": "test"}`

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("key", "test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	assertEvents(out, t, rawEvt)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionCustomStatusCodeAndCustomHeaders(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
port: 8080
path: /test
auth_type: headers
headers:
  key: test
custom_status_code: 201
custom_headers:
  success: true`))

	time.Sleep(1 * time.Second)

	rawEvt := `{"test": "test"}`
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddr), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("key", "test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status code %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	if resp.Header.Get("success") != "true" {
		t.Fatalf("expected header 'success' to be 'true', got '%s'", resp.Header.Get("success"))
	}

	assertEvents(out, t, rawEvt)

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

func assertEvents(out chan types.Event, t *testing.T, expected string) {
	readLines := []types.Event{}

	select {
	case event := <-out:
		readLines = append(readLines, event)
	case <-time.After(2 * time.Second):
		break
	}

	if len(readLines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(readLines))
	}
	if readLines[0].Line.Raw != expected {
		t.Fatalf(`expected %s, got '%+v'`, expected, readLines[0].Line)
	}
}

func TestStreamingAcquisitionTimeout(t *testing.T) {
	h := &HTTPSource{}
	_, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
port: 8080
path: /test
auth_type: headers
headers:
  key: test
timeout: 1s`))

	time.Sleep(1 * time.Second)

	slow := &slowReader{
		delay: 2 * time.Second,
		body:  []byte(`{"test": "delayed_payload"}`),
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/test", testHTTPServerAddr), slow)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Add("key", "test")
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
port: 8080
path: /test
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
  ca_cert: testdata/ca.crt`))

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
port: 8080
path: /test
auth_type: headers
headers:
  key: test
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
`))

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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/test", testHTTPServerAddrTLS), strings.NewReader(rawEvt))
	if err != nil {
		t.Fatalf("unable to create http request: %s", err)
	}
	req.Header.Add("key", "test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unable to post http request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	assertEvents(out, t, rawEvt)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}

func TestStreamingAcquisitionMTLS(t *testing.T) {
	h := &HTTPSource{}
	out, tomb := SetupAndRunHTTPSource(t, h, []byte(`
source: http
port: 8080
path: /test
auth_type: mtls
tls:
  server_cert: testdata/server.crt
  server_key: testdata/server.key
  ca_cert: testdata/ca.crt`))

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

	assertEvents(out, t, rawEvt)

	h.Server.Close()
	tomb.Kill(nil)
	tomb.Wait()
}
