package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestAllowlistList(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	_, err := lapi.DBClient.CreateAllowList(ctx, "test", "test", "", false)

	require.NoError(t, err)

	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	allowlists := models.GetAllowlistsResponse{}

	err = json.Unmarshal(w.Body.Bytes(), &allowlists)
	require.NoError(t, err)

	require.Len(t, allowlists, 1)
	require.Equal(t, "test", allowlists[0].Name)
}

func TestGetAllowlist(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	l, err := lapi.DBClient.CreateAllowList(ctx, "test", "test", "", false)

	require.NoError(t, err)

	added, err := lapi.DBClient.AddToAllowlist(ctx, l, []*models.AllowlistItem{
		{
			Value: "1.2.3.4",
		},
		{
			Value:      "2.3.4.5",
			Expiration: strfmt.DateTime(time.Now().Add(-time.Hour)), // expired
		},
	})

	require.NoError(t, err)
	assert.Equal(t, 2, added)

	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists/test?with_content=true", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	allowlist := models.GetAllowlistResponse{}

	err = json.Unmarshal(w.Body.Bytes(), &allowlist)
	require.NoError(t, err)

	require.Equal(t, "test", allowlist.Name)
	require.Len(t, allowlist.Items, 1)
	require.Equal(t, "1.2.3.4", allowlist.Items[0].Value)
}

func TestCheckInAllowlist(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	l, err := lapi.DBClient.CreateAllowList(ctx, "test", "test", "", false)

	require.NoError(t, err)

	added, err := lapi.DBClient.AddToAllowlist(ctx, l, []*models.AllowlistItem{
		{
			Value: "1.2.3.4",
		},
		{
			Value:      "2.3.4.5",
			Expiration: strfmt.DateTime(time.Now().Add(-time.Hour)), // expired
		},
	})

	require.NoError(t, err)
	assert.Equal(t, 2, added)

	// GET request, should return 200 and status in body
	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists/check/1.2.3.4", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	resp := models.CheckAllowlistResponse{}

	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	require.True(t, resp.Allowlisted)

	// GET request, should return 200 and status in body
	w = lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists/check/2.3.4.5", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	resp = models.CheckAllowlistResponse{}

	err = json.Unmarshal(w.Body.Bytes(), &resp)

	require.NoError(t, err)
	require.False(t, resp.Allowlisted)

	// GET request, should return 200 and status in body
	w = lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists/check/2.3.4.0%2F24", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	resp = models.CheckAllowlistResponse{}

	err = json.Unmarshal(w.Body.Bytes(), &resp)

	require.NoError(t, err)
	require.False(t, resp.Allowlisted)

	// HEAD request, should return 200
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/1.2.3.4", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	// HEAD request, should return 200
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/1.2.3.0%2F24", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	// HEAD request, should return 204
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/2.3.4.5", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusNoContent, w.Code)

	// HEAD request, should return 204
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/2.3.4.5%2F24", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestBulkCheckAllowlist(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// create an allowlist and add one live entry
	l, err := lapi.DBClient.CreateAllowList(ctx, "test", "test", "", false)
	require.NoError(t, err)

	added, err := lapi.DBClient.AddToAllowlist(ctx, l, []*models.AllowlistItem{
		{Value: "1.2.3.4"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, added)

	// craft a bulk check payload with one matching and one non-matching target
	reqBody := `{"targets":["1.2.3.4","2.3.4.5"]}`
	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists/check", strings.NewReader(reqBody), passwordAuthType)
	require.Equal(t, http.StatusOK, w.Code)

	// unmarshal and verify
	resp := models.BulkCheckAllowlistResponse{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Results, 1)

	// expect only "1.2.3.4" in the "test" allowlist, while "2.3.4.5" should not be in the response
	var match bool

	for _, r := range resp.Results {
		switch *r.Target {
		case "1.2.3.4":
			match = true

			assert.Equal(t, []string{"1.2.3.4 from test"}, r.Allowlists)
		default:
			t.Errorf("unexpected target %v", r.Target)
		}
	}

	require.True(t, match, "did not see result for 1.2.3.4")
}

func TestBulkCheckAllowlist_BadRequest(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// missing or empty body should yield 400
	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists/check", emptyBody, passwordAuthType)
	require.Equal(t, http.StatusBadRequest, w.Code)

	// malformed JSON should also yield 400
	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists/check", strings.NewReader("{invalid-json"), passwordAuthType)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAllowlistWriteLifecycle(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// 3 active decisions on 127.0.0.1 that the allowlist must expire
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists", strings.NewReader(`{"name":"office","description":"desc"}`), passwordAuthType)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists/office/items",
		strings.NewReader(`{"items":[{"value":"127.0.0.1"},{"value":"10.0.0.0/8","description":"lan"},{"value":"10.0.0.0/8"},{"value":"2001:db8::/32"}]}`), passwordAuthType)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"added":3,"decisions_expired":3}`, w.Body.String())

	w = lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/decisions", emptyBody, apiKeyAuthType)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "null", strings.TrimSpace(w.Body.String()), "decisions covered by the allowlist must be expired")

	// a value already present is skipped, not duplicated
	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/allowlists/office/items", strings.NewReader(`{"items":[{"value":"127.0.0.1"}]}`), passwordAuthType)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"added":0,"decisions_expired":0}`, w.Body.String())

	for _, tc := range []struct {
		value       string
		allowlisted bool
	}{
		{"127.0.0.1", true},
		{"10.20.30.40", true},
		{"2001:db8:1::1", true},
		{"192.168.1.1", false},
	} {
		allowlisted, _, err := lapi.DBClient.IsAllowlisted(ctx, tc.value)
		require.NoError(t, err)
		require.Equal(t, tc.allowlisted, allowlisted, tc.value)
	}

	w = lapi.RecordResponse(t, ctx, http.MethodDelete, "/v1/allowlists/office/items?value=10.0.0.0%2F8&value=1.1.1.1", emptyBody, passwordAuthType)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"removed":1}`, w.Body.String())

	allowlisted, _, err := lapi.DBClient.IsAllowlisted(ctx, "10.20.30.40")
	require.NoError(t, err)
	require.False(t, allowlisted)

	w = lapi.RecordResponse(t, ctx, http.MethodDelete, "/v1/allowlists/office", emptyBody, passwordAuthType)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

	allowlisted, _, err = lapi.DBClient.IsAllowlisted(ctx, "127.0.0.1")
	require.NoError(t, err)
	require.False(t, allowlisted, "items must go away with the allowlist")

	w = lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/allowlists/office", emptyBody, passwordAuthType)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAllowlistWriteErrors(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	_, err := lapi.DBClient.CreateAllowList(ctx, "local", "", "", false)
	require.NoError(t, err)

	_, err = lapi.DBClient.CreateAllowList(ctx, "console", "", "some-id", true)
	require.NoError(t, err)

	tests := []struct {
		name     string
		method   string
		url      string
		body     string
		authType string
		code     int
	}{
		{"create without name", http.MethodPost, "/v1/allowlists", `{"description":"x"}`, passwordAuthType, http.StatusBadRequest},
		{"create existing", http.MethodPost, "/v1/allowlists", `{"name":"local"}`, passwordAuthType, http.StatusConflict},
		{"create as bouncer", http.MethodPost, "/v1/allowlists", `{"name":"new"}`, apiKeyAuthType, http.StatusUnauthorized},
		{"add as bouncer", http.MethodPost, "/v1/allowlists/local/items", `{"items":[{"value":"1.2.3.4"}]}`, apiKeyAuthType, http.StatusUnauthorized},
		{"add invalid value", http.MethodPost, "/v1/allowlists/local/items", `{"items":[{"value":"1.2.3.4"},{"value":"not-an-ip"}]}`, passwordAuthType, http.StatusBadRequest},
		{"add no items", http.MethodPost, "/v1/allowlists/local/items", `{"items":[]}`, passwordAuthType, http.StatusBadRequest},
		{"add to missing list", http.MethodPost, "/v1/allowlists/nope/items", `{"items":[{"value":"1.2.3.4"}]}`, passwordAuthType, http.StatusNotFound},
		{"add to console list", http.MethodPost, "/v1/allowlists/console/items", `{"items":[{"value":"1.2.3.4"}]}`, passwordAuthType, http.StatusForbidden},
		{"remove without value", http.MethodDelete, "/v1/allowlists/local/items", "", passwordAuthType, http.StatusBadRequest},
		{"remove from console list", http.MethodDelete, "/v1/allowlists/console/items?value=1.2.3.4", "", passwordAuthType, http.StatusForbidden},
		{"delete console list", http.MethodDelete, "/v1/allowlists/console", "", passwordAuthType, http.StatusForbidden},
		{"delete missing list", http.MethodDelete, "/v1/allowlists/nope", "", passwordAuthType, http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := lapi.RecordResponse(t, ctx, tc.method, tc.url, strings.NewReader(tc.body), tc.authType)
			require.Equal(t, tc.code, w.Code, w.Body.String())
		})
	}

	// a rejected batch must not be partially applied
	allowlisted, _, err := lapi.DBClient.IsAllowlisted(ctx, "1.2.3.4")
	require.NoError(t, err)
	require.False(t, allowlisted)

	_, err = lapi.DBClient.GetAllowList(ctx, "console", false)
	require.NoError(t, err, "console list must survive the delete attempt")
}

func TestAllowlistWriteUntrustedIP(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	_, err := lapi.DBClient.CreateAllowList(ctx, "local", "", "", false)
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		url    string
		body   string
	}{
		{"create", http.MethodPost, "/v1/allowlists", `{"name":"new"}`},
		{"add", http.MethodPost, "/v1/allowlists/local/items", `{"items":[{"value":"1.2.3.4"}]}`},
		{"remove", http.MethodDelete, "/v1/allowlists/local/items?value=1.2.3.4", ""},
		{"delete", http.MethodDelete, "/v1/allowlists/local", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, tc.method, tc.url, strings.NewReader(tc.body))
			require.NoError(t, err)
			AddAuthHeaders(req, lapi.loginResp)
			req.RemoteAddr = "127.0.0.2:4242"
			lapi.router.ServeHTTP(w, req)
			require.Equal(t, http.StatusForbidden, w.Code)
			require.JSONEq(t, `{"message":"access forbidden from this IP (127.0.0.2)"}`, w.Body.String())
		})
	}

	allowlisted, _, err := lapi.DBClient.IsAllowlisted(ctx, "1.2.3.4")
	require.NoError(t, err)
	require.False(t, allowlisted)

	_, err = lapi.DBClient.GetAllowList(ctx, "local", false)
	require.NoError(t, err)

	_, err = lapi.DBClient.GetAllowList(ctx, "new", false)
	require.Error(t, err)
}
