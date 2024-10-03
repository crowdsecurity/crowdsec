package apiserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeartBeat(t *testing.T) {
	ctx := context.Background()
	lapi := SetupLAPITest(t, ctx)

	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse(t, ctx, "POST", "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 405, w.Code)
}
