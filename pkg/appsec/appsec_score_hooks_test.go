package appsec

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// End-to-end coverage of the threshold model the shipped
// appsec-bot-challenge-scoring configs implement: several hooks each credit a
// weight, a later hook acts only once the total crosses a bar.
//
// The decision lives in on_challenge_submit because that is the gate — a
// visitor must pass it to be issued a cookie, and the fingerprint measured
// there is the one sealed into that cookie.

// scoringSignalHooks mirrors the weights config: one hook per signal, keyed on
// the aggregate mismatch report, never on the running score.
func scoringSignalHooks() []Hook {
	return []Hook{
		{
			Filter: `EvaluateMismatches().Has("cdp")`,
			Apply:  []string{`AddRequestScore(100, "cdp")`},
		},
		{
			Filter: `EvaluateMismatches().Has("timezone_country")`,
			Apply:  []string{`AddRequestScore(5, "timezone_country")`},
		},
	}
}

// scoringPolicyHook mirrors a threshold config: refuse the submission, and with
// it the cookie, once the score crosses the bar.
func scoringPolicyHook() Hook {
	return Hook{
		Filter: `RequestScore() >= 75`,
		Apply:  []string{`RejectSubmission("request score " + string(RequestScore()) + ": " + join(RequestScoreReasons(), ","), "verbose")`},
	}
}

// fpEuropeParisClean is fpEuropeParisCDP with no library signal fired, so a
// US client IP leaves only the soft timezone_country mismatch.
func fpEuropeParisClean(t *testing.T) *challenge.FingerprintData {
	t.Helper()

	raw := `{
      "signals": {
        "device": {"platform": "MacIntel"},
        "browser": {
          "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120",
          "highEntropyValues": {"platform": "macOS"}
        },
        "locale": {
          "internationalization": {"timezone": "Europe/Paris"},
          "languages": {"language": "en"}
        }
      },
      "fsid": "FS_CLEAN", "nonce": "n", "time": 1, "url": "http://x/",
      "fastBotDetection": false,
      "fastBotDetectionDetails": {}
    }`

	fp := &challenge.FingerprintData{}
	require.NoError(t, json.Unmarshal([]byte(raw), fp))

	return fp
}

// newScoringState builds the in-band request state the challenge dispatcher
// hands to user hooks once it has a fingerprint to inspect.
func newScoringState(t *testing.T, rt *AppsecRuntimeConfig, fp *challenge.FingerprintData) (*AppsecRequestState, *ParsedRequest) {
	t.Helper()
	setupGeoIP(t)

	state := &AppsecRequestState{HookVars: map[string]string{}}
	state.ResetResponse(rt.Config)
	state.CurrentPhase = PhaseInBand // SendChallenge refuses to run out-of-band
	state.Fingerprint = fp

	req := newInBandRequest(http.MethodGet, "/", nil)
	req.ClientIP = testIPUS // geoips to US, so a Europe/Paris tz mismatches
	req.AppsecEngine = "test-engine"

	return state, req
}

// runSubmitHooks drives a compiled on_challenge_submit list the way
// ProcessOnChallengeRules does — state is passed so RejectSubmission can halt
// the remaining rules.
func runSubmitHooks(t *testing.T, rt *AppsecRuntimeConfig, hooks []Hook, fp *challenge.FingerprintData) *AppsecRequestState {
	t.Helper()

	compiled, err := buildHookList(t.Context(), hooks, hookOnChallengeSubmit, &appsecExprPatcher{})
	require.NoError(t, err)

	state, req := newScoringState(t, rt, fp)

	require.NoError(t, rt.processHooks(
		compiled,
		GetOnChallengeSubmitEnv(rt, state, req),
		"on_challenge_submit",
		state,
	))

	return state
}

// Two signals sum past the bar → no cookie is issued. RejectSubmission is
// terminal, so the trailing sentinel must not run; the accumulator doubles as
// the probe for that.
func TestOnChallengeSubmitScoreCrossesThreshold(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)

	hooks := append(scoringSignalHooks(),
		scoringPolicyHook(),
		Hook{Filter: `true`, Apply: []string{`AddRequestScore(1000, "sentinel")`}},
	)

	state := runSubmitHooks(t, rt, hooks, fpEuropeParisCDP(t))

	assert.Equal(t, 105, state.RequestScore.Total())
	assert.Equal(t, []string{"cdp", "timezone_country"}, state.RequestScore.Reasons())

	require.NotNil(t, state.SubmissionRejection)
	assert.Equal(t, "request score 105: cdp,timezone_country", state.SubmissionRejection.Reason)
	assert.True(t, state.HooksHalted)
	assert.NotContains(t, state.RequestScore.Reasons(), "sentinel", "sentinel hook must not have run")

	assert.Equal(t, "105", state.HookVars[hookVarRequestScore])
	assert.Equal(t, "cdp,timezone_country", state.HookVars[hookVarRequestScoreReasons])
	assert.Equal(t, "cdp=100,timezone_country=5", state.HookVars[hookVarRequestScoreDetail])
}

// The motivating case: one weak signal on its own must not act. Same hooks,
// same threshold — only the evidence differs.
func TestOnChallengeSubmitSingleWeakSignalStaysBelowThreshold(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)

	hooks := append(scoringSignalHooks(), scoringPolicyHook())
	state := runSubmitHooks(t, rt, hooks, fpEuropeParisClean(t))

	assert.Equal(t, 5, state.RequestScore.Total())
	assert.Equal(t, []string{"timezone_country"}, state.RequestScore.Reasons())

	assert.Nil(t, state.SubmissionRejection, "a lone weak signal must still be issued a cookie")
	assert.False(t, state.HooksHalted)
	assert.Equal(t, "5", state.HookVars[hookVarRequestScore])
}

// Hooks are appended across configs and evaluated in order, so a policy config
// listed ahead of the weights config reads an empty score and does nothing.
func TestOnChallengeSubmitPolicyBeforeSignalsDoesNotFire(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)

	hooks := append([]Hook{scoringPolicyHook()}, scoringSignalHooks()...)
	state := runSubmitHooks(t, rt, hooks, fpEuropeParisCDP(t))

	assert.Equal(t, 105, state.RequestScore.Total(), "signals still score, just too late")
	assert.Nil(t, state.SubmissionRejection, "policy hook saw an empty score")
}

// The accumulator is exposed in every request phase, not just the submit gate.
// on_challenge is the one that also has SendChallenge, so a custom config can
// escalate PoW difficulty from a score built there.
func TestOnChallengeScoreCanEscalateDifficulty(t *testing.T) {
	hooks := append(scoringSignalHooks(), Hook{
		Filter: `RequestScore() >= 75`,
		Apply:  []string{`SetChallengeDifficulty("high")`, `SendChallenge()`},
	})

	rt := newChallengeTestRuntime(t, hooks)
	state, req := newScoringState(t, rt, fpEuropeParisCDP(t))

	require.NoError(t, rt.processHooks(
		rt.CompiledOnChallenge,
		GetOnChallengeEnv(t.Context(), rt, state, req),
		"on_challenge",
		state,
	))

	assert.Equal(t, 105, state.RequestScore.Total())
	assert.True(t, state.RequireChallenge)
	assert.Equal(t, ChallengeRemediation, state.Response.Action)
	require.NotNil(t, state.ChallengeDifficulty)
	assert.Equal(t, challenge.PowDifficultyHigh, *state.ChallengeDifficulty)
}
