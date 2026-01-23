package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestGetScenarios(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create first machine with some scenarios
	machine1, err := lapi.DBClient.CreateMachine(ctx,
		ptr.Of("machine1"),
		&testPassword,
		"1.2.3.4",
		true,
		false,
		types.PasswordAuthType,
	)
	require.NoError(t, err)

	err = lapi.DBClient.UpdateMachineScenarios(ctx, "crowdsecurity/ssh-bf,crowdsecurity/http-bf", machine1.ID)
	require.NoError(t, err)

	// Create second machine with overlapping and unique scenarios
	machine2, err := lapi.DBClient.CreateMachine(ctx,
		ptr.Of("machine2"),
		&testPassword,
		"1.2.3.5",
		true,
		false,
		types.PasswordAuthType,
	)
	require.NoError(t, err)

	err = lapi.DBClient.UpdateMachineScenarios(ctx, "crowdsecurity/http-bf,custom/test", machine2.ID)
	require.NoError(t, err)

	// Test GET /scenarios with valid JWT
	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/scenarios", emptyBody, passwordAuthType)

	assert.Equal(t, http.StatusOK, w.Code)

	var scenarios []string
	err = json.Unmarshal(w.Body.Bytes(), &scenarios)
	require.NoError(t, err)

	// Should contain all unique scenarios
	assert.Contains(t, scenarios, "crowdsecurity/ssh-bf")
	assert.Contains(t, scenarios, "crowdsecurity/http-bf")
	assert.Contains(t, scenarios, "custom/test")
	assert.Len(t, scenarios, 3) // should remove duplicates
}

func TestGetScenariosUnauthorized(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Request without authentication
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/scenarios", emptyBody)
	require.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:1234"
	lapi.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetScenariosEmpty(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Test with no additional machines having scenarios
	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/scenarios", emptyBody, passwordAuthType)

	assert.Equal(t, http.StatusOK, w.Code)

	var scenarios []string
	err := json.Unmarshal(w.Body.Bytes(), &scenarios)
	require.NoError(t, err)

	// Should return a valid array (may be empty or contain scenarios from test machine)
	assert.NotNil(t, scenarios)
}
