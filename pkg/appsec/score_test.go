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

// A category left out, blank, or whitespace is the same thing: the signal is
// its own category. So a config that never heard of categories can still be
// read back by name, and the breakdown it emits is unchanged.
func TestRequestScoreWithoutCategories(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp")
	s.Add(3, "a", "")
	s.Add(4, "b", "   ")

	assert.Equal(t, []string{"cdp", "a", "b"}, s.Categories())
	assert.Equal(t, 100, s.ForCategories("cdp"), "readable as a category without opting in")
	assert.Equal(t, 107, s.ForCategories(), "no argument means the whole score")

	assert.False(t, s.HasExplicitCategories(), "nothing was grouped under another name")
	assert.Equal(t, "cdp=100,a=3,b=4", s.String())
}

func TestRequestScoreCategories(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp", "fingerprint")
	s.Add(15, "utc_timezone", "fingerprint")
	s.Add(30, "no_user_agent", "headers")
	s.Add(5, "slow_pow")

	assert.True(t, s.HasExplicitCategories())
	assert.Equal(t, []string{"fingerprint", "headers", "slow_pow"}, s.Categories())

	assert.Equal(t, 150, s.ForCategories())
	assert.Equal(t, 115, s.ForCategories("fingerprint"))
	assert.Equal(t, 145, s.ForCategories("fingerprint", "headers"))
	assert.Equal(t, 0, s.ForCategories("never_used"))
	assert.Equal(t, 115, s.ForCategories("fingerprint", "fingerprint"), "a repeated category must not count twice")

	assert.Equal(t, 5, s.ForCategories("slow_pow"), "an ungrouped signal is its own category")
	assert.Equal(t, "fingerprint=115,headers=30,slow_pow=5", s.CategoryDetail())
	// a label is namespaced only where the category says something the label
	// does not, so pre-category configs emit exactly what they always did
	assert.Equal(t,
		"fingerprint:cdp=100,fingerprint:utc_timezone=15,headers:no_user_agent=30,slow_pow=5",
		s.String())
}

// The property the whole category axis rests on: every live entry is in
// exactly one category, so the parts add up to the whole. Before categories
// defaulted to the label, ungrouped points were reachable by no filter at all.
func TestRequestScoreCategoriesPartitionTheTotal(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp", "fingerprint")
	s.Add(30, "no_user_agent", "headers")
	s.Add(5, "slow_pow")
	s.Set(11, "headers")

	assert.Equal(t, s.Total(), s.ForCategories(s.Categories()...))
}

// The same label under two categories is two contributions, reported apart,
// while a lookup by label still answers for the signal as a whole.
func TestRequestScoreSameLabelInTwoCategories(t *testing.T) {
	var s RequestScore

	s.Add(10, "mismatch", "fingerprint")
	s.Add(4, "mismatch", "headers")

	assert.Equal(t, 14, s.Total())
	assert.Equal(t, 14, s.For("mismatch"))
	assert.Equal(t, []string{"fingerprint:mismatch", "headers:mismatch"}, s.Reasons())
	assert.Equal(t, "fingerprint:mismatch=10,headers:mismatch=4", s.String())
	assert.Equal(t, 10, s.ForCategories("fingerprint"))
	assert.Equal(t, 4, s.ForCategories("headers"))
}

func TestRequestScoreSet(t *testing.T) {
	t.Run("without category it replaces the whole score", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Add(15, "utc_timezone")

		assert.Equal(t, 50, s.Set(50))
		assert.Equal(t, 50, s.Total())
		assert.Equal(t, 0, s.ForCategories("fingerprint"), "the overridden category stops counting")
	})

	t.Run("with a category it replaces only that category", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Add(15, "utc_timezone", "fingerprint")
		s.Add(30, "no_user_agent", "headers")

		assert.Equal(t, 80, s.Set(50, "fingerprint"))
		assert.Equal(t, 50, s.ForCategories("fingerprint"))
		assert.Equal(t, 30, s.ForCategories("headers"), "other categories are untouched")
		assert.Equal(t, 50, s.For(scoreSetLabel))
	})

	// The reason the override supersedes instead of deleting: an alert has to
	// be able to say which signals fired, even after policy overrode what
	// they were worth.
	t.Run("the overridden signals stay in the breakdown", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Add(15, "utc_timezone", "fingerprint")
		s.Set(20, "fingerprint")

		assert.Equal(t, 100, s.For("cdp"), "the signal still reports what it claimed")
		assert.Equal(t, 20, s.ForCategories("fingerprint"), "but it no longer counts toward the score")
		assert.Equal(t,
			"fingerprint:cdp=100,fingerprint:utc_timezone=15,fingerprint:set=20",
			s.String())
	})

	// An empty category is not a name, and naming none is how you reset the
	// whole score — so the two must not collapse into each other.
	t.Run("an empty category is skipped, not treated as no category", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")

		assert.Equal(t, 100, s.Set(3, ""), "the score is untouched")
		assert.Equal(t, 100, s.ForCategories("fingerprint"))
	})

	t.Run("each named category is set to the value", func(t *testing.T) {
		var s RequestScore

		s.Add(10, "a", "one")
		s.Add(10, "b", "two")

		assert.Equal(t, 100, s.Set(50, "one", "two"), "50 per category, not 50 total")
		assert.Equal(t, 50, s.ForCategories("one"))
		assert.Equal(t, 50, s.ForCategories("two"))
	})

	t.Run("a signal firing after the override counts on top of it", func(t *testing.T) {
		var s RequestScore

		s.Add(100, "cdp", "fingerprint")
		s.Set(20, "fingerprint")
		s.Add(7, "slow_pow", "fingerprint")

		assert.Equal(t, 27, s.ForCategories("fingerprint"))
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
	assert.Equal(t, "fingerprint:cdp=100,fingerprint:set=20", state.HookVars[hookVarRequestScoreReasons])
	assert.Equal(t, "fingerprint=20", state.HookVars[hookVarRequestScoreCategories])
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

// The key is rewritten on every mutation, so one that supersedes the last
// grouped signal has to clear it rather than leave the old value in the alert.
func TestCategoryHookVarClearedWhenGroupingGoesAway(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))
	require.Equal(t, "fingerprint=100", state.HookVars[hookVarRequestScoreCategories])

	require.NoError(t, w.SetRequestScore(state, 9))

	assert.Equal(t, "9", state.HookVars[hookVarRequestScore])
	assert.NotContains(t, state.HookVars, hookVarRequestScoreCategories)
}

// The one trap worth a dedicated test: no argument is "no filter", while an
// empty name is just a category nobody used.
func TestRequestScoreEmptyCategoryIsNotNoCategory(t *testing.T) {
	var s RequestScore

	s.Add(100, "cdp", "fingerprint")
	s.Add(20, "slow_pow")

	assert.Equal(t, 120, s.ForCategories(), "no argument does not filter")
	assert.Equal(t, 0, s.ForCategories(""), "an empty name matches nothing, like any unused name")
	assert.Equal(t, 20, s.ForCategories("slow_pow"), "an ungrouped signal is reached by its own name")

	assert.Equal(t, 100, s.ForCategories("fingerprint", ""), "a real name alongside an empty one still counts")
}
