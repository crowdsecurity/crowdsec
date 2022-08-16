package apiserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeartBeat(t *testing.T) {
	lapi := SetupLAPITest(t)

	w := lapi.RecordResponse(http.MethodGet, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse("POST", "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 405, w.Code)
}
