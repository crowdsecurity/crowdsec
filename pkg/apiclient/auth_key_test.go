package apiclient

import (
	"net/http"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestApiAuth(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.TraceLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")

		if r.Header.Get("X-Api-Key") == "ixu" {
			assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`null`))
			assert.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte(`{"message":"access forbidden"}`))
			assert.NoError(t, err)
		}
	})

	log.Printf("URL is %s", urlx)

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	defer teardown()

	//ok no answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	require.NoError(t, err)

	alert := DecisionsListOpts{IPEquals: ptr.Of("1.2.3.4")}
	_, resp, err := newcli.Decisions.List(ctx, alert)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)

	//ko bad token
	auth = &APIKeyTransport{
		APIKey: "bad",
	}

	newcli, err = NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	require.NoError(t, err)

	_, resp, err = newcli.Decisions.List(ctx, alert)

	log.Infof("--> %s", err)

	assert.Equal(t, http.StatusForbidden, resp.Response.StatusCode)

	cstest.RequireErrorMessage(t, err, "API error: access forbidden")

	//ko empty token
	auth = &APIKeyTransport{}

	newcli, err = NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	require.NoError(t, err)

	_, _, err = newcli.Decisions.List(ctx, alert)
	require.Error(t, err)

	log.Infof("--> %s", err)
	assert.Contains(t, err.Error(), "APIKey is empty")
}
