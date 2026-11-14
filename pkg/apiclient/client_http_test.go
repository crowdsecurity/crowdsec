package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

func TestNewRequestInvalid(t *testing.T) {
	ctx := t.Context()

	mux, urlx, teardown := setup()
	defer teardown()

	// missing slash in uri
	apiURL, err := url.Parse(urlx)
	require.NoError(t, err)

	client := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`{"code": 401, "message" : "bad login/password"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
	})

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	cstest.RequireErrorContains(t, err, "building request: BaseURL must have a trailing slash, but ")
}

// A transport error (here: nothing listening) must not yield a non-nil *Response
// wrapping a nil http.Response, or callers checking "resp != nil" would panic.
func TestNewRequestUnreachable(t *testing.T) {
	ctx := t.Context()

	// otherwise the client retries the failing dial for a few minutes
	require.NoError(t, fflag.DisableHttpRetryBackoff.Set(true))
	t.Cleanup(func() { _ = fflag.DisableHttpRetryBackoff.Set(false) })

	_, urlx, teardown := setup()
	teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	_, resp, err := client.UsageMetrics.Add(ctx, nil)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestNewRequestTimeout(t *testing.T) {
	ctx := t.Context()

	mux, urlx, teardown := setup()
	defer teardown()

	// missing slash in uri
	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	/*mock login*/
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	})

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, _, err = client.Alerts.List(ctx, AlertsListOpts{})
	cstest.RequireErrorMessage(t, err, "performing request: context deadline exceeded")
}
