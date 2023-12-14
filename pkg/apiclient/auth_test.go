package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiAuth(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if r.Header.Get("X-Api-Key") == "ixu" {
			assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`null`))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"access forbidden"}`))
		}
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()

	//ok no answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	alert := DecisionsListOpts{IPEquals: new(string)}
	*alert.IPEquals = "1.2.3.4"
	_, resp, err := newcli.Decisions.List(context.Background(), alert)
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	//ko bad token
	auth = &APIKeyTransport{
		APIKey: "bad",
	}

	newcli, err = NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	_, resp, err = newcli.Decisions.List(context.Background(), alert)

	log.Infof("--> %s", err)

	if resp.Response.StatusCode != http.StatusForbidden {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	assert.Contains(t, err.Error(), "API error: access forbidden")
	//ko empty token
	auth = &APIKeyTransport{}
	newcli, err = NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	_, _, err = newcli.Decisions.List(context.Background(), alert)
	require.Error(t, err)

	log.Infof("--> %s", err)
	assert.Contains(t, err.Error(), "APIKey is empty")
}
