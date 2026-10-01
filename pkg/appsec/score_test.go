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
	assert.Equal(t, "cdp=100,utc_timezone=15", state.HookVars[hookVarRequestScoreReasons])
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

// A category left out or blank is the same thing: the signal is its own
// category. So a config that never heard of categories can still be read back
// by name, and the breakdown it emits is unchanged.
func TestRequestScoreWithoutCategories(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp")
	s.Add(3, "a", "")
	s.Add(4, "b")

	assert.Equal(t, []string{"cdp", "a", "b"}, s.Categories())
	assert.Equal(t, 100, s.For("cdp"), "readable as a category without opting in")
	assert.Equal(t, 107, s.Total())

	assert.False(t, s.HasExplicitCategories(), "nothing was grouped under another name")
	assert.Equal(t, "cdp=100,a=3,b=4", s.String())
	assert.Equal(t, "cdp=100,a=3,b=4", s.CategoryDetail())
}

func TestRequestScoreCategories(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp", "fingerprint")
	s.Add(15, "utc_timezone", "fingerprint")
	s.Add(30, "no_user_agent", "headers")
	s.Add(5, "slow_pow")

	assert.True(t, s.HasExplicitCategories())
	assert.Equal(t, []string{"fingerprint", "headers", "slow_pow"}, s.Categories())

	assert.Equal(t, 150, s.Total())
	assert.Equal(t, 115, s.For("fingerprint"))
	assert.Equal(t, 30, s.For("headers"))
	assert.Equal(t, 5, s.For("slow_pow"), "an ungrouped signal is its own category")
	assert.Equal(t, 0, s.For("never_used"))

	assert.Equal(t, "fingerprint=115,headers=30,slow_pow=5", s.CategoryDetail())
	// a name is namespaced only where the category says something it does not,
	// so pre-category configs emit exactly what they always did
	assert.Equal(t,
		"fingerprint:cdp=100,fingerprint:utc_timezone=15,headers:no_user_agent=30,slow_pow=5",
		s.String())
}

// Rule 1, and the reason every detection gets a category: the parts add up to
// the whole, even once a reset has moved one of them.
func TestRequestScoreCategoriesSumToTheTotal(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp", "fingerprint")
	s.Add(30, "no_user_agent", "headers")
	s.Add(5, "slow_pow")
	s.Set(11, "headers")

	sum := 0
	for _, c := range s.Categories() {
		sum += s.For(c)
	}

	assert.Equal(t, s.Total(), sum)
	assert.Equal(t, 116, s.Total())
}

// The same name under two categories is two detections, reported apart, each
// counting toward its own category.
func TestRequestScoreSameNameInTwoCategories(t *testing.T) {
	var s RequestScore

	s.Add(10, "mismatch", "fingerprint")
	s.Add(4, "mismatch", "headers")

	assert.Equal(t, 14, s.Total())
	assert.Equal(t, []string{"fingerprint:mismatch", "headers:mismatch"}, s.Reasons())
	assert.Equal(t, "fingerprint:mismatch=10,headers:mismatch=4", s.String())
	assert.Equal(t, 10, s.For("fingerprint"))
	assert.Equal(t, 4, s.For("headers"))
}

func TestRequestScoreSet(t *testing.T) {
	t.Run("it replaces only the named category", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Add(15, "utc_timezone", "fingerprint")
		s.Add(30, "no_user_agent", "headers")

		assert.Equal(t, 80, s.Set(50, "fingerprint"))
		assert.Equal(t, 50, s.For("fingerprint"))
		assert.Equal(t, 30, s.For("headers"), "other categories are untouched")
	})

	// Rule 5. The detections are the record of what fired; a reset changes what
	// the request is worth, not the fact that the signals triggered.
	t.Run("the detections survive the reset", func(t *testing.T) {
		var s RequestScore

		s.Add(12, "utc", "foobar")
		s.Add(50, "cdp", "foobar")
		s.Set(10, "foobar")

		assert.Equal(t, 10, s.For("foobar"))
		assert.Equal(t, "foobar:utc=12,foobar:cdp=50", s.String(),
			"every detection is still listed, at the value it claimed")
		assert.Equal(t, []string{"foobar:utc", "foobar:cdp"}, s.Reasons())
	})

	// Traceability: without the marker, foobar=10 next to 62 points of
	// detections reads as a bug rather than a deliberate override.
	t.Run("an overridden category is marked", func(t *testing.T) {
		var s RequestScore

		s.Add(12, "utc", "foobar")
		s.Add(50, "cdp", "foobar")
		s.Add(5, "slow_pow")
		s.Set(10, "foobar")

		assert.Equal(t, "foobar=10(set),slow_pow=5", s.CategoryDetail())
	})

	t.Run("a later Add counts on top and keeps the marker", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Set(20, "fingerprint")
		s.Add(7, "slow_pow", "fingerprint")

		assert.Equal(t, 27, s.For("fingerprint"))
		assert.Equal(t, "fingerprint=27(set)", s.CategoryDetail(),
			"still not the sum of its detections")
	})

	t.Run("it creates a category nothing scored yet", func(t *testing.T) {
		var s RequestScore

		assert.Equal(t, 40, s.Set(40, "policy"))
		assert.Equal(t, []string{"policy"}, s.Categories())
		assert.Empty(t, s.String(), "no detection fired")
	})

	t.Run("setting zero leaves an explicit zero, not an absent category", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")

		assert.Equal(t, 0, s.Set(0, "fingerprint"))
		assert.False(t, s.Empty())
		assert.Equal(t, []string{"fingerprint"}, s.Categories())
	})
}

func TestSetRequestScoreMirrorsHookVars(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))
	require.NoError(t, w.SetRequestScore(state, 20, "fingerprint"))

	assert.Equal(t, "20", state.HookVars[hookVarRequestScore])
	assert.Equal(t, "fingerprint:cdp=100", state.HookVars[hookVarRequestScoreReasons])
	assert.Equal(t, "fingerprint=20(set)", state.HookVars[hookVarRequestScoreCategories])
}

// Every signal has a category now, so the key would otherwise appear on every
// alert repeating request_score_reasons verbatim.
func TestCategoryHookVarAbsentWithoutCategories(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 100, "cdp"))

	assert.Equal(t, "cdp=100", state.HookVars[hookVarRequestScoreReasons])
	assert.NotContains(t, state.HookVars, hookVarRequestScoreCategories)
}

// A reset has to name what it resets: there is no whole-score reset, and an
// empty category would silently be one.
func TestSetRequestScoreRejectsAnEmptyCategory(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))
	require.Error(t, w.SetRequestScore(state, 9, ""))

	assert.Equal(t, 100, state.RequestScore.Total(), "the score is untouched")
}
