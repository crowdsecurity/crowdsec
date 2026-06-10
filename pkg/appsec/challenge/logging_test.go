package challenge

import (
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runtimeWithCapturedLogger builds a lightweight validation runtime whose
// component logger captures entries at the given level.
func runtimeWithCapturedLogger(level log.Level) (*ChallengeRuntime, *logtest.Hook) {
	lg, hook := logtest.NewNullLogger()
	lg.SetLevel(level)

	entry := lg.WithField("module", "challenge")
	keys := testKeyRing()
	keys.logger = entry

	return &ChallengeRuntime{
		keys:          keys,
		powDifficulty: 8,
		cookieTTL:     time.Hour,
		spent:         newSpentSet(spentSetDefaultMaxEntries),
		logger:        entry,
	}, hook
}

func submitOnce(t *testing.T, c *ChallengeRuntime) {
	t.Helper()

	r, ts := freshChallenge(t)
	body := buildValidBody(t, c.powDifficulty, r, ts)

	req, err := http.NewRequest("POST", "http://example.com/submit", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	_, _, err = c.ValidateChallengeResponse(req, []byte(body))
	require.NoError(t, err)
}

// TestMergeFrom_LogLevel confirms log_level participates in the config merge.
func TestMergeFrom_LogLevel(t *testing.T) {
	dst := &Config{}
	lvl := log.DebugLevel
	dst.MergeFrom(&Config{LogLevel: &lvl})

	require.NotNil(t, dst.LogLevel)
	assert.Equal(t, log.DebugLevel, *dst.LogLevel)
}
