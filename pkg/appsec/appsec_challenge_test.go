package appsec

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// sharedChallengeRuntime lazily creates a single ChallengeRuntime for the
// whole package test run. NewChallengeRuntime runs the obfuscator WASM to
// generate a challenge JS bundle (~15-20s), so spinning one up per test is
// prohibitively slow and unnecessary for logic-only dispatcher tests.
var (
	sharedChallengeRuntimeOnce sync.Once
	sharedChallengeRuntimeInst *challenge.ChallengeRuntime
	sharedChallengeRuntimeErr  error
)

func getSharedChallengeRuntime(t *testing.T) *challenge.ChallengeRuntime {
	t.Helper()
	sharedChallengeRuntimeOnce.Do(func() {
		// Use context.Background so the runtime survives across tests.
		// Goroutines it spawns leak for the duration of the test binary; that's
		// acceptable here since the binary exits after tests complete.
		sharedChallengeRuntimeInst, sharedChallengeRuntimeErr = challenge.NewChallengeRuntime(context.Background())
	})
	require.NoError(t, sharedChallengeRuntimeErr)
	return sharedChallengeRuntimeInst
}

// newChallengeTestRuntime builds an AppsecRuntimeConfig wired with a real
// ChallengeRuntime for dispatcher tests. Provided on_challenge hooks are
// compiled via buildHookList, so tests can assert that user expressions run.
func newChallengeTestRuntime(t *testing.T, hooks []Hook) *AppsecRuntimeConfig {
	t.Helper()

	cr := getSharedChallengeRuntime(t)

	compiled, err := buildHookList(hooks, hookOnChallenge, &appsecExprPatcher{})
	require.NoError(t, err)

	logger := log.NewEntry(log.StandardLogger())

	cfg := &AppsecConfig{
		Name:                   "test-challenge",
		BouncerBlockedHTTPCode: http.StatusForbidden,
		BouncerPassedHTTPCode:  http.StatusOK,
		UserBlockedHTTPCode:    http.StatusForbidden,
		UserPassedHTTPCode:     http.StatusOK,
		DefaultPassAction:      AllowRemediation,
		DefaultRemediation:     BanRemediation,
	}

	return &AppsecRuntimeConfig{
		Name:                "test-challenge",
		Config:              cfg,
		Logger:              logger,
		ChallengeRuntime:    cr,
		CompiledOnChallenge: compiled,
	}
}

func newInBandRequest(method, path string, body []byte) *ParsedRequest {
	u, _ := url.Parse(path)
	return &ParsedRequest{
		HTTPRequest: &http.Request{
			Method: method,
			URL:    u,
			Header: http.Header{"User-Agent": []string{"go-test"}},
		},
		Body:     body,
		IsInBand: true,
	}
}

func TestProcessOnChallengeRulesNilRuntime(t *testing.T) {
	rt := &AppsecRuntimeConfig{
		Logger: log.NewEntry(log.StandardLogger()),
		Config: &AppsecConfig{},
	}
	state := &AppsecRequestState{}
	req := newInBandRequest(http.MethodGet, "/", nil)

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.False(t, state.RequireChallenge)
	assert.Nil(t, state.Fingerprint)
}

func TestProcessOnChallengeRulesServesPowWorker(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	req := newInBandRequest(http.MethodGet, challenge.ChallengePowWorkerPath, nil)

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.True(t, state.RequireChallenge)
	assert.Equal(t, ChallengeRemediation, state.Response.Action)
	assert.Equal(t, http.StatusOK, state.Response.UserHTTPResponseCode)
	assert.Equal(t, challenge.PowWorkerJS, state.Response.UserHTTPBodyContent)
	assert.Contains(t, state.Response.UserHeaders["Content-Type"], "application/javascript")
}

func TestProcessOnChallengeRulesSubmitInvalidBody(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	// Empty body → ValidateChallengeResponse fails; dispatcher returns failed JSON body.
	req := newInBandRequest(http.MethodPost, challenge.ChallengeSubmitPath, nil)

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.True(t, state.RequireChallenge)
	assert.JSONEq(t, bodyChallengeFailed, state.Response.UserHTTPBodyContent)
	assert.Contains(t, state.Response.UserHeaders["Content-Type"], "application/json")
	// No cookie is issued on failure.
	assert.Empty(t, state.Response.UserHTTPCookies)
}

func TestProcessOnChallengeRulesNoCookieSkipsUserHooks(t *testing.T) {
	// A hook that would unconditionally flip PendingAction must NOT run when
	// there is no fingerprint to inspect — this prevents nil-deref panics on
	// filters like `fingerprint.Bot.X`.
	rt := newChallengeTestRuntime(t, []Hook{
		{Apply: []string{"SetRemediation('allow')"}},
	})

	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	req := newInBandRequest(http.MethodGet, "/", nil)

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.Nil(t, state.Fingerprint)
	assert.Nil(t, state.PendingAction, "user hooks must not run when fingerprint is nil")
}

func TestProcessOnChallengeRulesInvalidCookieSkipsUserHooks(t *testing.T) {
	rt := newChallengeTestRuntime(t, []Hook{
		{Apply: []string{"SetReturnCode(418)"}},
	})

	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	// Attach an invalid cookie; ValidCookie fails silently and fingerprint stays nil.
	u, _ := url.Parse("/")
	httpReq := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: http.Header{
			"User-Agent": []string{"go-test"},
			"Cookie":     []string{challenge.ChallengeCookieName + "=garbage"},
		},
	}
	req := &ParsedRequest{HTTPRequest: httpReq, IsInBand: true}

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.Nil(t, state.Fingerprint)
	assert.Nil(t, state.PendingHTTPCode, "user hooks must not run when fingerprint is nil")
}

func TestSendChallengeNoOpWhenStoredDifficultyMeetsTarget(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)
	// Simulate a client that already proved the runtime-default difficulty.
	state.Fingerprint = &challenge.FingerprintData{}
	state.CookiePowDifficulty = rt.ChallengeRuntime.Difficulty()

	req := newInBandRequest(http.MethodGet, "/protected", nil)

	require.NoError(t, rt.SendChallenge(state, req))
	assert.False(t, state.RequireChallenge)
	assert.Empty(t, state.Response.UserHTTPBodyContent)
	assert.NotEqual(t, ChallengeRemediation, state.Response.Action)
}

func TestSendChallengeReIssuesWhenTargetExceedsStored(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)
	// Client proved medium; this request demands impossible.
	state.Fingerprint = &challenge.FingerprintData{}
	state.CookiePowDifficulty = challenge.PowDifficultyMedium
	impossible := challenge.PowDifficultyImpossible
	state.ChallengeDifficulty = &impossible

	req := newInBandRequest(http.MethodGet, "/protected", nil)

	require.NoError(t, rt.SendChallenge(state, req))
	assert.True(t, state.RequireChallenge)
	assert.Equal(t, ChallengeRemediation, state.Response.Action)
	assert.Contains(t, state.Response.UserHeaders["Content-Type"], "text/html")
	assert.NotEmpty(t, state.Response.UserHTTPBodyContent)
}

func TestSendChallengeNoOpWhenTargetLoweredBelowStored(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)
	// Client proved high; admin lowered the global target.
	state.Fingerprint = &challenge.FingerprintData{}
	state.CookiePowDifficulty = challenge.PowDifficultyHigh
	low := challenge.PowDifficultyLow
	state.ChallengeDifficulty = &low

	req := newInBandRequest(http.MethodGet, "/protected", nil)

	require.NoError(t, rt.SendChallenge(state, req))
	assert.False(t, state.RequireChallenge)
}

func TestProcessOnChallengeRulesInvalidSubmissionSkipsUserHooks(t *testing.T) {
	// A hook that would unconditionally flip PendingAction must NOT run when
	// the submission is invalid — the failed JSON body is the only response.
	rt := newChallengeTestRuntime(t, []Hook{
		{Apply: []string{"SetRemediation('allow')"}},
	})

	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	// Empty body → ValidateChallengeResponse fails.
	req := newInBandRequest(http.MethodPost, challenge.ChallengeSubmitPath, nil)

	require.NoError(t, rt.ProcessOnChallengeRules(state, req))
	assert.True(t, state.RequireChallenge)
	assert.JSONEq(t, bodyChallengeFailed, state.Response.UserHTTPBodyContent)
	assert.Nil(t, state.PendingAction, "user hooks must not run on invalid submission")
}
