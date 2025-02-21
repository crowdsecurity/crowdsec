package allowlists

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

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

func TestAppsecAllowlist(t *testing.T) {
	mux, urlx, teardown := setup()
	defer teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/allowlists", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("with_content") != "true" {
			t.Errorf("with_content not set")
		}

		w.WriteHeader(http.StatusOK)

		_, err = w.Write([]byte(`[{"name": "list1", "allowlist_id":"xxxx","console_managed":false,"created_at":"2025-02-11T14:47:35.839Z","description":"test_desc2",
		"items":[{"created_at":"2025-02-12T09:32:53.939Z","description":"desc_ip","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.3.2"},
		{"created_at":"2025-02-12T09:32:53.939Z","description":"desc_range","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.4.0/24"}]}]`))
		assert.NoError(t, err)
	})

	allowlistClient := NewAppsecAllowlist(client, log.NewEntry(log.StandardLogger()))

	err = allowlistClient.FetchAllowlists()
	require.NoError(t, err)

	res, reason := allowlistClient.IsAllowlisted("1.2.3.4")
	assert.False(t, res)
	assert.Empty(t, reason)

	res, reason = allowlistClient.IsAllowlisted("5.4.3.2")
	assert.True(t, res)
	assert.Equal(t, "5.4.3.2 from list1 (desc_ip)", reason)

	res, reason = allowlistClient.IsAllowlisted("5.4.4.42")
	assert.True(t, res)
	assert.Equal(t, "5.4.4.0/24 from list1 (desc_range)", reason)

	assert.Len(t, allowlistClient.ips, 1)
	assert.Len(t, allowlistClient.ranges, 1)

	err = allowlistClient.FetchAllowlists()
	require.NoError(t, err)

	// No duplicates should be added
	assert.Len(t, allowlistClient.ips, 1)
	assert.Len(t, allowlistClient.ranges, 1)
}
