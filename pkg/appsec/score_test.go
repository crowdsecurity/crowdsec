package appsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestScoreZeroValue(t *testing.T) {
	var s RequestScore

	assert.Equal(t, 0, s.Total())
	assert.Empty(t, s.Reasons())
	assert.Empty(t, s.String())
	assert.True(t, s.Empty())
	assert.Equal(t, 0, s.For("never_fired"))
}

func TestRequestScoreAccumulates(t *testing.T) {
	var s RequestScore

	assert.Equal(t, 15, s.Add(15, "utc_timezone"))
	assert.Equal(t, 115, s.Add(100, "cdp"))
	assert.Equal(t, 120, s.Add(5, "timezone_country"))

	assert.Equal(t, 120, s.Total())
	// first-seen order, not insertion-sorted or map order
	assert.Equal(t, []string{"utc_timezone", "cdp", "timezone_country"}, s.Reasons())
	assert.Equal(t, "utc_timezone=15,cdp=100,timezone_country=5", s.String())
}

// A repeated reason sums rather than replacing: that is what CRS-style
// "every matched rule adds its severity" needs. The reason keeps the
// position it was first seen at, so output stays stable.
func TestRequestScoreRepeatedReasonSums(t *testing.T) {
	var s RequestScore

	s.Add(5, "crs_sqli")
	s.Add(15, "ua_mobile")
	s.Add(10, "crs_sqli")

	assert.Equal(t, 30, s.Total())
	assert.Equal(t, 15, s.For("crs_sqli"))
	assert.Equal(t, []string{"crs_sqli", "ua_mobile"}, s.Reasons())
	assert.Equal(t, "crs_sqli=15,ua_mobile=15", s.String())
}

func TestRequestScoreNegativeAndZeroPoints(t *testing.T) {
	var s RequestScore

	s.Add(15, "utc_timezone")
	s.Add(-20, "trusted_gpu")
	assert.Equal(t, -5, s.Total(), "credits are not clamped at zero")

	// A zero-point contribution is observe-only: it must not move the total
	// but must still show up in the breakdown.
	s.Add(0, "observed_only")
	assert.Equal(t, -5, s.Total())
	assert.Contains(t, s.Reasons(), "observed_only")
	assert.Equal(t, 0, s.For("observed_only"))

	// Signals fired but canceled out — still not Empty().
	assert.False(t, s.Empty())
}

func TestRequestScoreBlankReasonNormalized(t *testing.T) {
	var s RequestScore

	s.Add(3, "")
	s.Add(4, "   ")

	assert.Equal(t, 7, s.Total())
	assert.Equal(t, []string{unspecifiedScoreReason}, s.Reasons())
	assert.Equal(t, 7, s.For(unspecifiedScoreReason))
}

func TestRequestScoreReasonsIsACopy(t *testing.T) {
	var s RequestScore

	s.Add(1, "a")

	reasons := s.Reasons()
	reasons[0] = "mutated"

	assert.Equal(t, []string{"a"}, s.Reasons(), "callers must not be able to mutate internal state")
}

func TestAddRequestScoreMirrorsHookVars(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 100, "cdp"))
	require.NoError(t, w.AddRequestScore(state, 15, "utc_timezone"))

	assert.Equal(t, "115", state.HookVars[hookVarRequestScore])
	assert.Equal(t, "cdp,utc_timezone", state.HookVars[hookVarRequestScoreReasons])
	assert.Equal(t, "cdp=100,utc_timezone=15", state.HookVars[hookVarRequestScoreDetail])
}

// ResetResponse clears response fields only. The score is per-request
// evaluation state (like HookVars, LastMismatchReport and ChallengeExempt)
// and must survive it — ClearResponse is exported and callable mid-request.
func TestResetResponseDoesNotClearRequestScore(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 45, "headless_screen_resolution"))

	state.ResetResponse(&AppsecConfig{})

	assert.Equal(t, 45, state.RequestScore.Total())
	assert.Equal(t, []string{"headless_screen_resolution"}, state.RequestScore.Reasons())
	assert.Equal(t, "45", state.HookVars[hookVarRequestScore])
}

func TestRequestScoreIsPerRequest(t *testing.T) {
	w := makeRuntime()

	first := &AppsecRequestState{HookVars: map[string]string{}}
	require.NoError(t, w.AddRequestScore(first, 100, "cdp"))
	assert.Equal(t, 100, first.RequestScore.Total())

	fresh := &AppsecRequestState{}
	assert.Equal(t, 0, fresh.RequestScore.Total())
	assert.Empty(t, fresh.RequestScore.Reasons())
}
