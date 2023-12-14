package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/version"
)

func TestNewRequestInvalid(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()
	//missing slash in uri
	apiURL, err := url.Parse(urlx)
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
	assert.Contains(t, err.Error(), `building request: BaseURL must have a trailing slash, but `)
}

func TestNewRequestTimeout(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()
	//missing slash in uri
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
		time.Sleep(2 * time.Second)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	assert.Contains(t, err.Error(), `performing request: context deadline exceeded`)
}
