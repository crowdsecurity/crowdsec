package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestAllowlistList(t *testing.T) {
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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

	// HEAD request, should return 200
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/1.2.3.4", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusOK, w.Code)

	// HEAD request, should return 204
	w = lapi.RecordResponse(t, ctx, http.MethodHead, "/v1/allowlists/check/2.3.4.5", emptyBody, passwordAuthType)

	require.Equal(t, http.StatusNoContent, w.Code)
}
