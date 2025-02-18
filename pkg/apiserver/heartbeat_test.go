package apiserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeartBeat(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 405, w.Code)
}
