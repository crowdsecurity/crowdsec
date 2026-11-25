package appsec

import (
	"net/http"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/hookreq"
)

var reqStages = []hookStage{hookPreEval, hookPostEval, hookOnMatch, hookOnChallenge, hookOnChallengeSubmit}

func newHookTestRequest(t *testing.T) *ParsedRequest {
	t.Helper()

	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/admin/login?x=1", http.NoBody)
	require.NoError(t, err)

	httpReq.RemoteAddr = "1.2.3.4"
	httpReq.RequestURI = "/admin/login?x=1"
	httpReq.Header.Set("User-Agent", "curl/8.0")
	httpReq.Header.Set("Referer", "http://example.com/")
	httpReq.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	httpReq.Header.Set("X-Custom", "foo")
	httpReq.AddCookie(&http.Cookie{Name: "session", Value: "abc"})

	return &ParsedRequest{HTTPRequest: httpReq, HookRequest: hookreq.New(httpReq)}
}

// The members of `req` that hook authors (and the hub) rely on.
func TestHookReqSurface(t *testing.T) {
	tests := []struct {
		expr string
		want any
	}{
		{`req.URL.Path`, "/admin/login"},
		{`req.URL.RawQuery`, "x=1"},
		{`req.UserAgent()`, "curl/8.0"},
		{`req.Referer()`, "http://example.com/"},
		{`req.RemoteAddr`, "1.2.3.4"},
		{`req.Method`, "POST"},
		{`req.Host`, "example.com"},
		{`req.RequestURI`, "/admin/login?x=1"},
		{`req.Proto`, "HTTP/1.1"},
		{`req.Header.Get("X-Custom")`, "foo"},
		{`req.Header["X-Custom"][0]`, "foo"},
		{`req.Cookie("session").Value`, "abc"},
		{`len(req.Cookies())`, 1},
		{`req.Cookies()[0].Name`, "session"},
		{`JA4H(req)`, "po11cr03dede_962b88454c92_3f3af1ecebbd_a47daa9671e7"},
	}

	for _, stage := range reqStages {
		for _, tc := range tests {
			t.Run(stage.String()+"/"+tc.expr, func(t *testing.T) {
				h := &Hook{Filter: tc.expr}
				require.NoError(t, h.Build(t.Context(), stage, nil))

				state := &AppsecRequestState{HookVars: map[string]string{}}
				env := scoreEnvForStage(stage, makeRuntime(), state, newHookTestRequest(t))

				got, err := expr.Run(h.FilterExpr, env)
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	}
}

func TestHookReqAcceptLanguageMismatch(t *testing.T) {
	for _, stage := range []hookStage{hookPreEval, hookPostEval, hookOnChallenge, hookOnChallengeSubmit} {
		t.Run(stage.String(), func(t *testing.T) {
			h := &Hook{Filter: `fingerprint.AcceptLanguageMismatch(req)`}
			require.NoError(t, h.Build(t.Context(), stage, nil))

			fp := &challenge.FingerprintData{}
			fp.Signals.Locale.Languages.Language = "en"
			state := &AppsecRequestState{HookVars: map[string]string{}, Fingerprint: fp}
			env := scoreEnvForStage(stage, makeRuntime(), state, newHookTestRequest(t))

			got, err := expr.Run(h.FilterExpr, env)
			require.NoError(t, err)
			require.Equal(t, true, got)
		})
	}
}
