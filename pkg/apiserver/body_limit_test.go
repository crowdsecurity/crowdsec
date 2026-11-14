package apiserver

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
)

// When the MaxBytesReader cap is exceeded, encoding/json surfaces this error
// string from the underlying read. The handlers return it verbatim in the 400
// response, which lets us assert the middleware is the actual rejecter (as
// opposed to a parse or validation error on a truncated body).
const bodyTooLargeMsg = "http: request body too large"

// TestBodyLimit_UnauthenticatedOverLimit posts a JSON document larger than the
// 2 MiB cap on the unauthenticated /v1/watchers endpoint and asserts the
// middleware trips.
func TestBodyLimit_UnauthenticatedOverLimit(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	body := oversizedJSON(t, int(middlewares.UnauthenticatedBodyLimit)+1024)

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), bodyTooLargeMsg)
}

// TestBodyLimit_UnauthenticatedUnderLimit sends the same style of request but
// well under the 2 MiB cap, so the middleware must not fire. We don't care
// whether registration ultimately succeeds — only that the failure (if any) is
// not a body-size rejection.
func TestBodyLimit_UnauthenticatedUnderLimit(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	// Valid registration payload, definitely below 2 MiB.
	body := `{"machine_id":"test","password":"test"}`

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.NotContains(t, w.Body.String(), bodyTooLargeMsg)
}

// TestBodyLimit_AuthenticatedAboveUnauthCap verifies that an authenticated
// endpoint accepts bodies larger than the unauthenticated cap. The alert
// payload here is not semantically valid, so we don't expect 2xx — but the
// rejection must not come from the body-size middleware.
func TestBodyLimit_AuthenticatedAboveUnauthCap(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Build a payload ~4 MiB: over the unauth 2 MiB cap, well under the 50 MiB
	// auth cap. Uses the alert-array shape so we get past the JSON top-level
	// type check and into field validation (which will fail — that's fine).
	size := int(middlewares.UnauthenticatedBodyLimit) * 2
	body := `[{"message":"` + strings.Repeat("a", size) + `"}]`

	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", strings.NewReader(body), passwordAuthType)

	assert.NotContains(t, w.Body.String(), bodyTooLargeMsg)
}

// TestBodyLimit_AuthenticatedOverLimit posts a payload above the 50 MiB auth
// cap and asserts the middleware trips.
func TestBodyLimit_AuthenticatedOverLimit(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	size := int(middlewares.AuthenticatedBodyLimit) + 1024
	body := `[{"message":"` + strings.Repeat("a", size) + `"}]`

	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", strings.NewReader(body), passwordAuthType)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), bodyTooLargeMsg)
}

// TestBodyLimit_GzipDecompressedSize confirms the cap is enforced on the
// *decompressed* size: a small compressed payload that expands past the
// unauthenticated cap must be rejected.
func TestBodyLimit_GzipDecompressedSize(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	// Pad a valid-looking JSON doc with a large whitespace run; zeros/spaces
	// compress to a tiny payload but expand past the 2 MiB cap.
	decompressed := `{"machine_id":"test","password":"test","_pad":"` +
		strings.Repeat(" ", int(middlewares.UnauthenticatedBodyLimit)+1024) + `"}`

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write([]byte(decompressed))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.Less(t, compressed.Len(), int(middlewares.UnauthenticatedBodyLimit),
		"compressed body must be under the cap so only the decompressed size can trip it")

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", bytes.NewReader(compressed.Bytes()))
	require.NoError(t, err)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), bodyTooLargeMsg)
}

// oversizedJSON returns a syntactically-valid JSON object whose raw size is at
// least `size` bytes, via a long string field.
func oversizedJSON(t *testing.T, size int) string {
	t.Helper()
	return `{"machine_id":"test","password":"test","_pad":"` + strings.Repeat("a", size) + `"}`
}
