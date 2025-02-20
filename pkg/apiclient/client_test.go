package apiclient

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"runtime"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

/*this is a ripoff of google/go-github approach :
- setup a test http server along with a client that is configured to talk to test server
- each test will then bind handler for the method(s) they want to try
*/

func setup() (*http.ServeMux, string, func()) {
	return setupWithPrefix("v1")
}

func setupWithPrefix(urlPrefix string) (*http.ServeMux, string, func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux := http.NewServeMux()
	baseURLPath := "/" + urlPrefix

	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}

// toUNCPath converts a Windows file path to a UNC path.
// This is necessary because the Go http package does not support Windows file paths.
func toUNCPath(path string) (string, error) {
	colonIdx := strings.Index(path, ":")
	if colonIdx == -1 {
		return "", fmt.Errorf("invalid path format, missing drive letter: %s", path)
	}

	// URL parsing does not like backslashes
	remaining := strings.ReplaceAll(path[colonIdx+1:], "\\", "/")
	uncPath := "//localhost/" + path[:colonIdx] + "$" + remaining

	return uncPath, nil
}

func setupUnixSocketWithPrefix(t *testing.T, socket string, urlPrefix string) (mux *http.ServeMux, serverURL string, teardown func()) {
	var err error
	if runtime.GOOS == "windows" {
		socket, err = toUNCPath(socket)
		require.NoError(t, err, "converting to UNC path")
	}

	mux = http.NewServeMux()
	baseURLPath := "/" + urlPrefix

	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	server := httptest.NewUnstartedServer(apiHandler)
	l, _ := net.Listen("unix", socket)
	_ = server.Listener.Close()
	server.Listener = l
	server.Start()

	return mux, socket, server.Close
}

func testMethod(t *testing.T, r *http.Request, want string) {
	t.Helper()
	assert.Equal(t, want, r.Method)
}

func TestNewClientOk(t *testing.T) {
	ctx := t.Context()
	mux, urlx, teardown := setup()
	defer teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, resp, err := client.Alerts.List(ctx, AlertsListOpts{})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
}

func TestNewClientOk_UnixSocket(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	socket := path.Join(tmpDir, "socket")

	mux, urlx, teardown := setupUnixSocketWithPrefix(t, socket, "v1")
	defer teardown()

	apiURL, err := url.Parse(urlx)
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}
	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, resp, err := client.Alerts.List(ctx, AlertsListOpts{})
	if err != nil {
		t.Fatalf("test Unable to list alerts : %+v", err)
	}

	if resp.Response.StatusCode != http.StatusOK {
		t.Fatalf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusCreated)
	}
}

func TestNewClientKo(t *testing.T) {
	ctx := t.Context()

	mux, urlx, teardown := setup()
	defer teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`{"code": 401, "message" : "bad login/password"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	cstest.RequireErrorContains(t, err, `API error: bad login/password`)

	log.Printf("err-> %s", err)
}

func TestNewDefaultClient(t *testing.T) {
	ctx := t.Context()

	mux, urlx, teardown := setup()
	defer teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewDefaultClient(apiURL, "/v1", "", nil)
	require.NoError(t, err)

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`{"code": 401, "message" : "brr"}`))
		assert.NoError(t, err)
	})

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	cstest.RequireErrorMessage(t, err, "performing request: API error: brr")

	log.Printf("err-> %s", err)
}

func TestNewDefaultClient_UnixSocket(t *testing.T) {
	ctx := t.Context()

	tmpDir := t.TempDir()
	socket := path.Join(tmpDir, "socket")

	mux, urlx, teardown := setupUnixSocketWithPrefix(t, socket, "v1")
	defer teardown()

	apiURL, err := url.Parse(urlx)
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	client, err := NewDefaultClient(apiURL, "/v1", "", nil)
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`{"code": 401, "message" : "brr"}`))
		assert.NoError(t, err)
	})

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	assert.Contains(t, err.Error(), `performing request: API error: brr`)
	log.Printf("err-> %s", err)
}

func TestNewClientRegisterKO(t *testing.T) {
	ctx := t.Context()

	apiURL, err := url.Parse("http://127.0.0.1:4242/")
	require.NoError(t, err)

	_, err = RegisterClient(ctx, &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})

	if runtime.GOOS == "windows" {
		cstest.RequireErrorContains(t, err, " No connection could be made because the target machine actively refused it.")
	} else {
		cstest.RequireErrorContains(t, err, "dial tcp 127.0.0.1:4242: connect: connection refused")
	}
}

func TestNewClientRegisterOK(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.TraceLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	/*mock login*/
	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := RegisterClient(ctx, &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	require.NoError(t, err)

	log.Printf("->%T", client)
}

func TestNewClientRegisterOK_UnixSocket(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.TraceLevel)

	tmpDir := t.TempDir()
	socket := path.Join(tmpDir, "socket")

	mux, urlx, teardown := setupUnixSocketWithPrefix(t, socket, "v1")
	defer teardown()

	/*mock login*/
	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	apiURL, err := url.Parse(urlx)
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	client, err := RegisterClient(ctx, &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	if err != nil {
		t.Fatalf("while registering client : %s", err)
	}

	log.Printf("->%T", client)
}

func TestNewClientBadAnswer(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.TraceLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	/*mock login*/
	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`bad`))
		assert.NoError(t, err)
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	_, err = RegisterClient(ctx, &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	cstest.RequireErrorContains(t, err, "API error: http code 401, response: bad")
}
