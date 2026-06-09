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

// TestLogLevel_KEpochOnlyAtDebug is the security guard for the diagnostic
// logging: the per-epoch key k_epoch is written at debug and NEVER at
// info/warn (it is forgeable signing material).
func TestLogLevel_KEpochOnlyAtDebug(t *testing.T) {
	// debug: the validated-submission line appears and carries k_epoch.
	c, hook := runtimeWithCapturedLogger(log.DebugLevel)
	submitOnce(t, c)

	var submission *log.Entry
	for _, e := range hook.AllEntries() {
		if e.Message == "validated submission" {
			submission = e
		}
	}
	require.NotNil(t, submission, "debug must emit the validated-submission line")
	require.Contains(t, submission.Data, "k_epoch", "debug submission log must include k_epoch")
	assert.NotEmpty(t, submission.Data["k_epoch"])

	// info: no k_epoch in any entry, and no per-submission line.
	c, hook = runtimeWithCapturedLogger(log.InfoLevel)
	submitOnce(t, c)
	for _, e := range hook.AllEntries() {
		assert.NotContains(t, e.Data, "k_epoch", "k_epoch must not be logged at info (line %q)", e.Message)
		assert.NotEqual(t, "validated submission", e.Message)
	}

	// warn: silent — no submission line, no k_epoch.
	c, hook = runtimeWithCapturedLogger(log.WarnLevel)
	submitOnce(t, c)
	for _, e := range hook.AllEntries() {
		assert.NotContains(t, e.Data, "k_epoch")
		assert.NotEqual(t, "validated submission", e.Message)
	}
}

// TestMergeFrom_LogLevel confirms log_level participates in the config merge.
func TestMergeFrom_LogLevel(t *testing.T) {
	dst := &Config{}
	lvl := log.DebugLevel
	dst.MergeFrom(&Config{LogLevel: &lvl})

	require.NotNil(t, dst.LogLevel)
	assert.Equal(t, log.DebugLevel, *dst.LogLevel)
}
