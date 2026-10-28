package appsec

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rejection has to name the rules that produced the score. `signals` only
// lists what fpscanner measured, so without this a score contributed by a
// custom detection leaves no trace in the log at all.
func TestWithRequestScoreAddsBreakdown(t *testing.T) {
	state := &AppsecRequestState{}
	state.RequestScore.Add(100, "realm_font_mismatch")
	state.RequestScore.Add(30, "gpu_mismatch")

	entry := withRequestScore(log.NewEntry(log.StandardLogger()), state)

	require.Equal(t, 130, entry.Data["score"])
	require.Equal(t, "realm_font_mismatch=100,gpu_mismatch=30", entry.Data["score_detail"])
}

// An unscored request must not gain empty fields.
func TestWithRequestScoreNoopWhenEmpty(t *testing.T) {
	base := log.NewEntry(log.StandardLogger())

	got := withRequestScore(base, &AppsecRequestState{})

	assert.Same(t, base, got)
	assert.NotContains(t, got.Data, "score")
	assert.NotContains(t, got.Data, "score_detail")
}
