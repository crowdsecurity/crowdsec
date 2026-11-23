package appsec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParsedRequestReplyDoesNotBlockAfterHandlerExit(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", http.NoBody)
	request.Header.Set(IPHeaderName, "192.0.2.1")
	request.Header.Set(URIHeaderName, "/")
	request.Header.Set(VerbHeaderName, http.MethodGet)

	parsed, err := NewParsedRequestFromRequest(request, log.NewEntry(log.New()), BodySettings{})
	require.NoError(t, err)

	// A runner may finish after the HTTP handler has left on shutdown.
	select {
	case parsed.ResponseChannel <- AppsecTempResponse{}:
	default:
		t.Fatal("runner reply would block with no remaining handler")
	}
}
