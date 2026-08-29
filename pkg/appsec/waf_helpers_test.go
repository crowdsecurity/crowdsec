package appsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBotChallengeHooksCompile guards the env maps: a hook referencing
// MatchKnownBot (global helper) and ExemptFromChallenge(reason) must compile in
// every phase exposing them.
func TestBotChallengeHooksCompile(t *testing.T) {
	for _, stage := range []hookStage{hookPreEval, hookPostEval, hookOnMatch} {
		h := &Hook{
			Filter: `MatchKnownBot(req.RemoteAddr, req.UserAgent(), req.URL.Path, "legit_bots/gptbot.json")`,
			Apply:  []string{`ExemptFromChallenge("gptbot")`},
		}
		require.NoError(t, h.Build(t.Context(), stage, nil), "stage %v", stage)
	}
}

// TestRequestScoreHooksCompile guards the score accumulator env entries: the
// four helpers must compile in every request phase. The filter also exercises
// the expr builtins the shipped threshold configs rely on to build a reject
// reason (string() over an int, join() over a []string).
func TestRequestScoreHooksCompile(t *testing.T) {
	stages := []hookStage{hookPreEval, hookPostEval, hookOnMatch, hookOnChallenge, hookOnChallengeSubmit}
	for _, stage := range stages {
		h := &Hook{
			Filter: `RequestScore() >= 45 && RequestScoreFor("cdp") > 0 && string(RequestScore()) != "" && join(RequestScoreReasons(), ",") != ""`,
			Apply:  []string{`AddRequestScore(15, "utc_timezone")`},
		}
		require.NoError(t, h.Build(t.Context(), stage, &appsecExprPatcher{}), "stage %v", stage)
	}
}

// on_load has no request state, so scoring there must fail at config load
// rather than silently no-op.
func TestRequestScoreHooksRejectedInOnLoad(t *testing.T) {
	h := &Hook{Apply: []string{`AddRequestScore(15, "utc_timezone")`}}
	require.Error(t, h.Build(t.Context(), hookOnLoad, &appsecExprPatcher{}))
}

// The accumulator is plain Go state: referencing it must not drag the
// challenge runtime (WASM VM, obfuscator, keyring) into existence.
func TestRequestScoreDoesNotNeedChallengeRuntime(t *testing.T) {
	patcher := &appsecExprPatcher{}
	h := &Hook{
		Filter: `RequestScore() >= 45`,
		Apply:  []string{`AddRequestScore(15, "utc_timezone")`},
	}
	require.NoError(t, h.Build(t.Context(), hookPreEval, patcher))
	assert.False(t, patcher.NeedWASMVM)
}

func TestRequestScoreEnvClosuresBindState(t *testing.T) {
	state := &AppsecRequestState{HookVars: map[string]string{}}
	env := GetOnChallengeEnv(t.Context(), makeRuntime(), state, &ParsedRequest{})

	add := env["AddRequestScore"].(func(int, string) error)
	total := env["RequestScore"].(func() int)
	reasons := env["RequestScoreReasons"].(func() []string)
	forReason := env["RequestScoreFor"].(func(string) int)

	assert.Equal(t, 0, total())

	require.NoError(t, add(100, "cdp"))
	require.NoError(t, add(15, "utc_timezone"))

	assert.Equal(t, 115, total())
	assert.Equal(t, []string{"cdp", "utc_timezone"}, reasons())
	assert.Equal(t, 100, forReason("cdp"))
	assert.Equal(t, 115, state.RequestScore.Total())
}

// TestExemptFromChallengeSetsFlag verifies ExemptFromChallenge(reason) flips the
// per-request ChallengeExempt flag (which SendChallenge later honors), and that
// the flag is per-request state.
func TestExemptFromChallengeSetsFlag(t *testing.T) {
	state := &AppsecRequestState{HookVars: map[string]string{}}
	env := GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, state, &ParsedRequest{})

	exempt := env["ExemptFromChallenge"].(func(string) error)

	assert.False(t, state.ChallengeExempt)
	require.NoError(t, exempt("gptbot"))
	assert.True(t, state.ChallengeExempt)

	// per-request state: a fresh state starts clean
	fresh := &AppsecRequestState{HookVars: map[string]string{}}
	_ = GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, fresh, &ParsedRequest{})
	assert.False(t, fresh.ChallengeExempt)
}

// TestParseChallengeCookieTTLArg covers the GrantChallengeCookie optional TTL
// argument parsing: no args / empty string yield a nil override (use runtime
// default), a parseable duration yields a positive pointer, and malformed /
// non-positive / multi-arg inputs surface as errors so hook authors see a
// precise diagnostic instead of silent fallback.
func TestParseChallengeCookieTTLArg(t *testing.T) {
	t.Run("no args → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty string → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{""})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("valid duration", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{"1h30m"})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, 90*time.Minute, *got)
	})

	t.Run("malformed duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"forever"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid GrantChallengeCookie TTL")
	})

	t.Run("non-positive duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"-5m"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("multiple TTL args rejected", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"1h", "2h"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most one TTL argument")
	})
}
