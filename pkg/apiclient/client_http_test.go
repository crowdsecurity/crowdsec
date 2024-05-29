package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

func TestNewRequestInvalid(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()

	//missing slash in uri
	apiURL, err := url.Parse(urlx)
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     cwversion.UserAgent(),
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

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
	cstest.RequireErrorContains(t, err, "building request: BaseURL must have a trailing slash, but ")
}

func TestNewRequestTimeout(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()

	// missing slash in uri
	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     cwversion.UserAgent(),
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	cstest.RequireErrorMessage(t, err, "performing request: context deadline exceeded")
}
