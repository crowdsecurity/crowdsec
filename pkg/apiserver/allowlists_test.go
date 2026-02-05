package apiserver

import (
	"encoding/json"
	"net/http"
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
