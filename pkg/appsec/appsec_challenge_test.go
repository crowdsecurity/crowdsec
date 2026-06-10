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

	compiled, err := buildHookList(t.Context(), hooks, hookOnChallenge, &appsecExprPatcher{})
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

// TestRejectSubmissionSetsState confirms the helper sets the state field;
// downstream ProcessOnChallengeRules submit branch keys off this to refuse
// cookie issuance.
func TestRejectSubmissionSetsState(t *testing.T) {
	rt := &AppsecRuntimeConfig{
		Logger: log.NewEntry(log.StandardLogger()),
		Config: &AppsecConfig{},
	}
	state := &AppsecRequestState{}

	require.NoError(t, rt.RejectSubmission(state, "bot detected"))
	require.NotNil(t, state.SubmissionRejection)
	assert.Equal(t, "bot detected", state.SubmissionRejection.Reason)

	// Empty reason gets a default placeholder.
	state2 := &AppsecRequestState{}
	require.NoError(t, rt.RejectSubmission(state2, ""))
	assert.Equal(t, "submission rejected by on_challenge_submit", state2.SubmissionRejection.Reason)
}

// TestGrantChallengeCookieIssuesRedirect confirms the helper mints a
// cookie, stamps allowlist fingerprint + bypass state, and produces a
// 307 challenge response carrying the Location header and Set-Cookie
// back to the visitor. The 307 is necessary because GenerateResponse
// only serialises UserCookies on ChallengeRemediation responses.
func TestGrantChallengeCookieIssuesRedirect(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	req := newInBandRequest(http.MethodGet, "/protected?a=1", nil)

	require.NoError(t, rt.GrantChallengeCookie(state, req, "Googlebot/2.1", nil))

	require.NotNil(t, state.Fingerprint)
	assert.True(t, state.Fingerprint.Allowlisted)
	assert.Equal(t, "Googlebot/2.1", state.Fingerprint.AllowlistReason)
	assert.True(t, state.ChallengeBypassed, "ChallengeBypassed must be set to suppress later SendChallenge")

	assert.Equal(t, ChallengeRemediation, state.Response.Action, "must produce a challenge-action response so the cookie is serialised")
	assert.Equal(t, http.StatusTemporaryRedirect, state.Response.UserHTTPResponseCode, "must be a 307 redirect")
	assert.True(t, state.RequireChallenge, "RequireChallenge must be flagged so the wire response carries the cookie")

	require.Len(t, state.Response.UserHTTPCookies, 1, "allowlist cookie must be appended")
	require.NotNil(t, state.Response.UserHeaders)
	require.Contains(t, state.Response.UserHeaders, "Location")
	assert.Equal(t, []string{"/protected?a=1"}, state.Response.UserHeaders["Location"])
	assert.Equal(t, challenge.GrantRedirectBody, state.Response.UserHTTPBodyContent, "body must be the redirect fallback page")
}

// TestGrantAllowlistCookieInlineNoRedirect confirms the submit-phase
// variant attaches the cookie without producing a redirect response.
// on_challenge_submit returns the challenge-submit JSON envelope the
// client is already awaiting; a 307 would break the client JS state
// machine.
func TestGrantAllowlistCookieInlineNoRedirect(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	req := newInBandRequest(http.MethodPost, challenge.ChallengeSubmitPath, nil)

	require.NoError(t, rt.GrantAllowlistCookieInline(state, req, "submit-allowlist", nil))

	require.NotNil(t, state.Fingerprint)
	assert.True(t, state.Fingerprint.Allowlisted)
	assert.Equal(t, "submit-allowlist", state.Fingerprint.AllowlistReason)
	assert.True(t, state.ChallengeBypassed)
	require.Len(t, state.Response.UserHTTPCookies, 1, "cookie must ride on the existing envelope")
	assert.NotEqual(t, http.StatusTemporaryRedirect, state.Response.UserHTTPResponseCode, "inline variant must NOT emit a redirect status")
	assert.NotContains(t, state.Response.UserHeaders, "Location", "inline variant must not set Location")
}

// TestSendChallengeNoOpAfterGrantChallengeCookie covers the bypass guard:
// after GrantChallengeCookie sets ChallengeBypassed, a subsequent
// SendChallenge call in the same request is a no-op (must not overwrite
// the 307 redirect response body with a challenge page).
func TestSendChallengeNoOpAfterGrantChallengeCookie(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)
	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	req := newInBandRequest(http.MethodGet, "/", nil)
	require.NoError(t, rt.GrantChallengeCookie(state, req, "ua-pass", nil))
	require.True(t, state.ChallengeBypassed)

	cookiesBefore := len(state.Response.UserHTTPCookies)
	bodyBefore := state.Response.UserHTTPBodyContent
	statusBefore := state.Response.UserHTTPResponseCode

	require.NoError(t, rt.SendChallenge(state, req))

	assert.Equal(t, cookiesBefore, len(state.Response.UserHTTPCookies), "cookie set must be unchanged")
	assert.Equal(t, bodyBefore, state.Response.UserHTTPBodyContent, "redirect body must not be overwritten")
	assert.Equal(t, statusBefore, state.Response.UserHTTPResponseCode, "redirect status must not be overwritten")
}

// TestProcessOnChallengeRulesAllowlistCookiePropagatesFlag asserts the
// cookie-valid branch of ProcessOnChallengeRules copies the Allowlisted +
// AllowlistReason fields from the decoded cookie into state.Fingerprint.
func TestProcessOnChallengeRulesAllowlistCookiePropagatesFlag(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)

	// Mint an allowlist cookie via the public helper, then re-attach it to a
	// regular request and run the dispatcher.
	mintReq := newInBandRequest(http.MethodGet, "/", nil)
	ck, err := rt.ChallengeRuntime.SealAllowlistCookie(mintReq.HTTPRequest, "test-bypass", nil)
	require.NoError(t, err)

	u, _ := url.Parse("/protected")
	getReq := &ParsedRequest{
		HTTPRequest: &http.Request{
			Method: http.MethodGet,
			URL:    u,
			Header: http.Header{
				"User-Agent": []string{"go-test"},
				"Cookie":     []string{challenge.ChallengeCookieName + "=" + ck.Val},
			},
		},
		IsInBand: true,
	}

	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	require.NoError(t, rt.ProcessOnChallengeRules(state, getReq))
	require.NotNil(t, state.Fingerprint, "valid allowlist cookie must populate fingerprint")
	assert.True(t, state.Fingerprint.Allowlisted)
	assert.Equal(t, "test-bypass", state.Fingerprint.AllowlistReason)
	assert.True(t, state.ChallengeBypassed,
		"allowlist cookie must set ChallengeBypassed so later SendChallenge is a no-op")
}

// TestAllowlistCookieRoundtripBypassesSendChallenge covers the actual bug
// reported against GrantChallengeCookie: a follow-up request carrying the
// minted allowlist cookie must not be re-challenged. Without the
// ChallengeBypassed propagation in the cookie-valid branch, SendChallenge
// would happily render a challenge page on top of the cookie.
func TestAllowlistCookieRoundtripBypassesSendChallenge(t *testing.T) {
	rt := newChallengeTestRuntime(t, nil)

	mintReq := newInBandRequest(http.MethodGet, "/", nil)
	ck, err := rt.ChallengeRuntime.SealAllowlistCookie(mintReq.HTTPRequest, "roundtrip", nil)
	require.NoError(t, err)

	u, _ := url.Parse("/protected")
	replayReq := &ParsedRequest{
		HTTPRequest: &http.Request{
			Method: http.MethodGet,
			URL:    u,
			Header: http.Header{
				"User-Agent": []string{"go-test"},
				"Cookie":     []string{challenge.ChallengeCookieName + "=" + ck.Val},
			},
		},
		IsInBand: true,
	}

	state := &AppsecRequestState{}
	state.ResetResponse(rt.Config)

	require.NoError(t, rt.ProcessOnChallengeRules(state, replayReq))
	require.NotNil(t, state.Fingerprint)
	require.True(t, state.ChallengeBypassed, "replayed allowlist cookie must flip ChallengeBypassed")

	// Anything downstream calling SendChallenge must now be a no-op.
	bodyBefore := state.Response.UserHTTPBodyContent
	statusBefore := state.Response.UserHTTPResponseCode
	actionBefore := state.Response.Action

	require.NoError(t, rt.SendChallenge(state, replayReq))

	assert.Equal(t, actionBefore, state.Response.Action, "SendChallenge must not set ChallengeRemediation")
	assert.NotEqual(t, ChallengeRemediation, state.Response.Action,
		"a replayed allowlist cookie must not produce a challenge response")
	assert.Equal(t, bodyBefore, state.Response.UserHTTPBodyContent, "challenge body must not be written")
	assert.Equal(t, statusBefore, state.Response.UserHTTPResponseCode, "challenge status must not overwrite")
	assert.False(t, state.RequireChallenge, "RequireChallenge must stay false on bypassed replay")
}
