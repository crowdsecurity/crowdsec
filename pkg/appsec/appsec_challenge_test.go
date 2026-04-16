package appsec

import (
	"net/http"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// newChallengeTestRuntime builds an AppsecRuntimeConfig wired with a real
// ChallengeRuntime for dispatcher tests. Provided on_challenge hooks are
// compiled via buildHookList, so tests can assert that user expressions run.
func newChallengeTestRuntime(t *testing.T, hooks []Hook) *AppsecRuntimeConfig {
	t.Helper()

	cr, err := challenge.NewChallengeRuntime(t.Context())
	require.NoError(t, err)

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

func TestSendChallengeNoOpWhenFingerprintSet(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)
	// Simulate an already-validated fingerprint (cookie populated by on_challenge).
	state.Fingerprint = &challenge.FingerprintData{}

	req := newInBandRequest(http.MethodGet, "/protected", nil)

	require.NoError(t, rt.SendChallenge(state, req))
	assert.False(t, state.RequireChallenge)
	assert.Empty(t, state.Response.UserHTTPBodyContent)
	assert.NotEqual(t, ChallengeRemediation, state.Response.Action)
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
