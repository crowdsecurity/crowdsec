package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

// cancelOnDeleted cancels the request context as soon as the "deleted" part of
// the stream begins, like a bouncer that disconnects in the middle of a pull.
type cancelOnDeleted struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnDeleted) Write(b []byte) (int, error) {
	if strings.Contains(string(b), `"deleted"`) {
		w.cancel()
	}

	return w.ResponseRecorder.Write(b)
}

func (w *cancelOnDeleted) WriteString(s string) (int, error) {
	if strings.Contains(s, `"deleted"`) {
		w.cancel()
	}

	return w.ResponseRecorder.WriteString(s)
}

func TestStreamDeltaClientDisconnect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := t.Context()

	dbClient, err := database.NewClient(ctx, &csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: filepath.Join(t.TempDir(), "test.sqlite"),
	}, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = dbClient.Ent.Close()
	})

	c := &Controller{DBClient: dbClient}

	reqCtx, cancel := context.WithCancel(ctx)
	rec := &cancelOnDeleted{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}

	gctx, _ := gin.CreateTestContext(rec)
	gctx.Request = httptest.NewRequest(http.MethodGet, "/v1/decisions/stream", nil).WithContext(reqCtx)

	lastPull := time.Now().UTC().Add(-time.Minute)

	err = c.streamDecisions(gctx, &ent.Bouncer{LastPull: &lastPull}, time.Now().UTC(), map[string][]string{})
	require.ErrorIs(t, err, database.QueryFail)

	// even when the expired query fails mid-stream, the response must end as valid JSON
	assert.Equal(t, `{"new": [], "deleted": []}`, rec.Body.String())
}
