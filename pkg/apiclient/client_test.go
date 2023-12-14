package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/version"
)

/*this is a ripoff of google/go-github approach :
- setup a test http server along with a client that is configured to talk to test server
- each test will then bind handler for the method(s) they want to try
*/

func setup() (mux *http.ServeMux, serverURL string, teardown func()) {
	return setupWithPrefix("v1")
}

func setupWithPrefix(urlPrefix string) (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()
	baseURLPath := "/" + urlPrefix

	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}

func testMethod(t *testing.T, r *http.Request, want string) {
	t.Helper()

	if got := r.Method; got != want {
		t.Errorf("Request method: %v, want %v", got, want)
	}
}

func TestNewClientOk(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}
	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, resp, err := client.Alerts.List(context.Background(), AlertsListOpts{})
	if err != nil {
		t.Fatalf("test Unable to list alerts : %+v", err)
	}

	if resp.Response.StatusCode != http.StatusOK {
		t.Fatalf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusCreated)
	}
}

func TestNewClientKo(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}
	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code": 401, "message" : "bad login/password"}`))
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, _, err = client.Alerts.List(context.Background(), AlertsListOpts{})
	assert.Contains(t, err.Error(), `API error: bad login/password`)
	log.Printf("err-> %s", err)
}

func TestNewDefaultClient(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewDefaultClient(apiURL, "/v1", "", nil)
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code": 401, "message" : "brr"}`))
	})
	_, _, err = client.Alerts.List(context.Background(), AlertsListOpts{})
	assert.Contains(t, err.Error(), `performing request: API error: brr`)
	log.Printf("err-> %s", err)
}

func TestNewClientRegisterKO(t *testing.T) {
	apiURL, err := url.Parse("http://127.0.0.1:4242/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	_, err = RegisterClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	if runtime.GOOS != "windows" {
		assert.Contains(t, fmt.Sprintf("%s", err), "dial tcp 127.0.0.1:4242: connect: connection refused")
	} else {
		assert.Contains(t, fmt.Sprintf("%s", err), " No connection could be made because the target machine actively refused it.")
	}
}

func TestNewClientRegisterOK(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	mux, urlx, teardown := setup()

	defer teardown()

	/*mock login*/
	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := RegisterClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	if err != nil {
		t.Fatalf("while registering client : %s", err)
	}

	log.Printf("->%T", client)
}

func TestNewClientBadAnswer(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	mux, urlx, teardown := setup()

	defer teardown()

	/*mock login*/
	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`bad`))
	})
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	_, err = RegisterClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	assert.Contains(t, fmt.Sprintf("%s", err), `invalid body: invalid character 'b' looking for beginning of value`)
}
