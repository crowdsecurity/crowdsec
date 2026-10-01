package appsec

import (
	"context"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
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

// scoringStages are the phases that expose the request-score family. on_load
// is deliberately absent: see TestRequestScoreHooksRejectedInOnLoad.
var scoringStages = []hookStage{hookPreEval, hookPostEval, hookOnMatch, hookOnChallenge, hookOnChallengeSubmit}

func scoreEnvForStage(stage hookStage, w *AppsecRuntimeConfig, state *AppsecRequestState, req *ParsedRequest) map[string]any {
	ctx := context.Background()

	switch stage {
	case hookPreEval:
		return GetPreEvalEnv(ctx, w, state, req)
	case hookPostEval:
		return GetPostEvalEnv(ctx, w, state, req)
	case hookOnMatch:
		return GetOnMatchEnv(ctx, w, state, req, pipeline.Event{})
	case hookOnChallenge:
		return GetOnChallengeEnv(ctx, w, state, req)
	case hookOnChallengeSubmit:
		return GetOnChallengeSubmitEnv(ctx, w, state, req)
	case hookOnLoad:
		return GetOnLoadEnv(w)
	}

	return nil
}

// The score helpers are expr.Function, so they reach the request through the
// context rather than a closure. That wiring is per stage and easy to forget
// when a phase is added, so every scoring stage is driven end to end here:
// compile the rule, run it, and check the real state moved.
func TestRequestScoreHelpersBindStateInEveryStage(t *testing.T) {
	for _, stage := range scoringStages {
		t.Run(stage.String(), func(t *testing.T) {
			w := makeRuntime()
			state := &AppsecRequestState{HookVars: map[string]string{}}
			req := &ParsedRequest{}

			h := &Hook{Apply: []string{
				`AddRequestScore(100, "cdp", "fingerprint")`,
				`AddRequestScore(15, "utc_timezone")`,
				`SetRequestScore(5, "fingerprint")`,
			}}
			require.NoError(t, h.Build(t.Context(), stage, &appsecExprPatcher{}))

			env := scoreEnvForStage(stage, w, state, req)
			for _, program := range h.ApplyExpr {
				_, err := expr.Run(program, env)
				require.NoError(t, err)
			}

			// 100 in "fingerprint" replaced by 5, plus utc_timezone's own 15
			assert.Equal(t, 20, state.RequestScore.Total())
			assert.Equal(t, 5, state.RequestScore.For("fingerprint"))
			assert.Equal(t, 15, state.RequestScore.For("utc_timezone"))
			assert.Equal(t, "20", state.HookVars[hookVarRequestScore])
		})
	}
}

// The prototypes are the contract rule authors write against: a wrong type or
// arity must fail at config load, not on the first live request, where the
// error would abort the whole hook chain.
func TestRequestScorePrototypes(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr string
	}{
		{name: "add without category", expr: `AddRequestScore(10, "cdp")`},
		{name: "add with category", expr: `AddRequestScore(10, "cdp", "bot")`},
		{name: "add rejects a second category", expr: `AddRequestScore(10, "cdp", "bot", "x")`, wantErr: "too many arguments"},
		// With two prototypes registered, expr reports any mismatch as an
		// arity error rather than naming the offending type. Still a config
		// load failure, just a blunter message.
		{name: "add rejects a non-string label", expr: `AddRequestScore(10, 5)`, wantErr: "arguments to call AddRequestScore"},
		{name: "score takes no argument", expr: `RequestScore() > 0`},
		{name: "score rejects an argument", expr: `RequestScore("bot") > 0`, wantErr: "too many arguments"},
		{name: "score for a category", expr: `RequestScoreFor("bot") > 0`},
		{name: "score for rejects a non-string", expr: `RequestScoreFor(1) > 0`, wantErr: "cannot use int"},
		{name: "set with a category", expr: `SetRequestScore(50, "bot")`},
		{name: "set requires a category", expr: `SetRequestScore(50)`, wantErr: "not enough arguments"},
		{name: "set rejects a second category", expr: `SetRequestScore(50, "bot", "fingerprint")`, wantErr: "too many arguments"},
		{name: "set requires a value", expr: `SetRequestScore("bot", "x")`, wantErr: "cannot use string"},
		{name: "categories takes no argument", expr: `"bot" in RequestScoreCategories()`},
		{name: "categories rejects an argument", expr: `RequestScoreCategories("bot")`, wantErr: "too many arguments"},
		// An empty label or category is a rule bug, but a string is a string:
		// it can only be caught at runtime. See
		// TestAddRequestScoreRejectsAnEmptyLabel and
		// TestSetRequestScoreRejectsAnEmptyCategory.
		{name: "add compiles with an empty label", expr: `AddRequestScore(10, "")`},
		{name: "set compiles with an empty category", expr: `SetRequestScore(10, "")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Hook{Apply: []string{tc.expr}}).Build(t.Context(), hookPreEval, &appsecExprPatcher{})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
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

// A reset has to name what it resets. The realistic way to get an empty
// category is a hook_vars lookup that was never set, so it is caught in the
// helper where a literal and a variable look the same — and in an apply block
// the error costs only the offending expression.
func TestSetRequestScoreRejectsAnEmptyCategoryFromARule(t *testing.T) {
	for _, tc := range []struct{ name, expr string }{
		{name: "literal", expr: `SetRequestScore(3, "")`},
		{name: "variable", expr: `SetRequestScore(3, hook_vars["never_set"])`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(log.ErrorLevel)

			w := &AppsecRuntimeConfig{Logger: log.NewEntry(logger)}
			state := &AppsecRequestState{HookVars: map[string]string{}}
			require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))

			h := Hook{Apply: []string{tc.expr, `AddRequestScore(5, "slow_pow")`}}
			require.NoError(t, h.Build(t.Context(), hookPostEval, &appsecExprPatcher{}))

			env := scoreEnvForStage(hookPostEval, w, state, &ParsedRequest{})
			require.NoError(t, w.processHooks([]Hook{h}, env, "post_eval", state),
				"a rejected category must not abort the stage")

			assert.Equal(t, 105, state.RequestScore.Total(), "the reset did not happen")
			assert.Equal(t, 100, state.RequestScore.For("fingerprint"))

			require.Len(t, hook.Entries, 1)
			assert.Equal(t, log.ErrorLevel, hook.LastEntry().Level)
			assert.Contains(t, hook.LastEntry().Message, "category cannot be empty")
		})
	}
}

// A detection shipped at 0 points records itself without moving the decision,
// which leaves the category list as the only way a rule can tell it fired:
// every score read for it returns 0 by construction.
func TestRequestScoreCategoriesSeesZeroScoredSignals(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}

	h := &Hook{Filter: `"experimental" in RequestScoreCategories()`}
	require.NoError(t, h.Build(t.Context(), hookOnChallengeSubmit, &appsecExprPatcher{}))

	env := scoreEnvForStage(hookOnChallengeSubmit, w, state, &ParsedRequest{})

	// nothing scored yet: the list has to be usable, not nil
	fired, err := expr.Run(h.FilterExpr, env)
	require.NoError(t, err)
	require.False(t, fired.(bool))

	require.NoError(t, w.AddRequestScore(state, 45, "headless_screen_resolution", "fingerprint"))
	require.NoError(t, w.AddRequestScore(state, 0, "canvas_noise", "experimental"))

	fired, err = expr.Run(h.FilterExpr, env)
	require.NoError(t, err)
	require.True(t, fired.(bool), "a zero-scored category is still in the list")

	assert.Equal(t, 45, state.RequestScore.Total(), "and it must not move the decision")
	assert.Equal(t, 0, state.RequestScore.For("experimental"))
	assert.Equal(t, "fingerprint=45,experimental=0", state.HookVars[hookVarRequestScoreCategories])
}

// An empty label names neither axis, since the category defaults to it. The
// helper rejects it, and this pins the part that makes rejecting affordable:
// in an apply block the error costs only the offending expression.
func TestAddRequestScoreRejectsAnEmptyLabel(t *testing.T) {
	for _, tc := range []struct{ name, expr string }{
		{name: "literal", expr: `AddRequestScore(10, "")`},
		{name: "variable", expr: `AddRequestScore(10, hook_vars["never_set"])`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(log.ErrorLevel)

			w := &AppsecRuntimeConfig{Logger: log.NewEntry(logger)}
			state := &AppsecRequestState{HookVars: map[string]string{}}

			h := Hook{Apply: []string{tc.expr, `AddRequestScore(5, "cdp")`}}
			require.NoError(t, h.Build(t.Context(), hookPreEval, &appsecExprPatcher{}))

			env := scoreEnvForStage(hookPreEval, w, state, &ParsedRequest{})
			require.NoError(t, w.processHooks([]Hook{h}, env, "pre_eval", state),
				"a rejected label must not abort the stage")

			assert.Equal(t, 5, state.RequestScore.Total(), "only the well-formed call scored")
			assert.Equal(t, []string{"cdp"}, state.RequestScore.Reasons())

			require.Len(t, hook.Entries, 1)
			assert.Equal(t, log.ErrorLevel, hook.LastEntry().Level)
			assert.Contains(t, hook.LastEntry().Message, "reason cannot be empty")
		})
	}
}
