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

			// 100 in "fingerprint" replaced by 5, plus the uncategorized 15
			assert.Equal(t, 20, state.RequestScore.Total())
			assert.Equal(t, 5, state.RequestScore.ForCategories("fingerprint"))
			assert.Equal(t, 15, state.RequestScore.Uncategorized())
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
		{name: "score with no category", expr: `RequestScore() > 0`},
		{name: "score with one category", expr: `RequestScore("bot") > 0`},
		{name: "score with many categories", expr: `RequestScore("bot", "fingerprint") > 0`},
		{name: "score rejects a non-string category", expr: `RequestScore(1) > 0`, wantErr: "cannot use int"},
		{name: "set with no category", expr: `SetRequestScore(50)`},
		{name: "set with one category", expr: `SetRequestScore(50, "bot")`},
		{name: "set with many categories", expr: `SetRequestScore(50, "bot", "fingerprint")`},
		{name: "set requires a value", expr: `SetRequestScore("bot")`, wantErr: "cannot use string"},
		{name: "uncategorized takes no argument", expr: `RequestScoreUncategorized() > 0`},
		// An empty label normalizes to "unspecified"; an empty category is a
		// mistake, but it is reported at runtime, not here. See
		// TestEmptyCategoryWarnsAndScoresZero.
		{name: "add accepts an empty label", expr: `AddRequestScore(10, "")`},
		{name: "score accepts an empty category", expr: `RequestScore("") > 0`},
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

// An empty category is a mistake whichever way it is written, so it is
// reported from the helper, where a literal and a variable look the same. It
// warns rather than erroring: an error would abort the rest of the hook chain,
// which is worse than a rule that scores zero.
func TestEmptyCategoryWarnsAndScoresZero(t *testing.T) {
	for _, tc := range []struct{ name, filter string }{
		{name: "literal", filter: `RequestScore("")`},
		{name: "variable", filter: `RequestScore(hook_vars["never_set"])`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(log.WarnLevel)

			w := &AppsecRuntimeConfig{Logger: log.NewEntry(logger)}
			state := &AppsecRequestState{HookVars: map[string]string{}}
			require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))

			h := &Hook{Filter: tc.filter}
			require.NoError(t, h.Build(t.Context(), hookPostEval, &appsecExprPatcher{}))

			got, err := expr.Run(h.FilterExpr, scoreEnvForStage(hookPostEval, w, state, &ParsedRequest{}))
			require.NoError(t, err, "an empty category must not abort the hook chain")
			assert.Equal(t, 0, got)

			require.Len(t, hook.Entries, 1)
			assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
			assert.Contains(t, hook.LastEntry().Message, "empty category argument")
		})
	}
}
