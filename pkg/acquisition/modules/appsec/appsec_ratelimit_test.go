package appsecacquisition

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type rateLimitHarness struct {
	t      *testing.T
	engine string
	runner *AppsecRunner
	out    chan pipeline.Event
}

func newRateLimitHarness(t *testing.T, preEval ...appsec.Hook) *rateLimitHarness {
	t.Helper()

	engine := "ratelimit-" + uuid.NewString()
	cfg := appsec.AppsecConfig{Name: engine, Logger: log.WithField("test", t.Name()), PreEval: preEval}

	rt, err := cfg.Build(t.Context(), &cwhub.Hub{})
	require.NoError(t, err)

	out := make(chan pipeline.Event, 128)
	rt.OutChan = out

	runner := &AppsecRunner{
		UUID:          uuid.NewString(),
		logger:        log.WithField("test", t.Name()),
		AppsecRuntime: rt,
	}
	require.NoError(t, runner.Init(t.TempDir()))

	return &rateLimitHarness{t: t, engine: engine, runner: runner, out: out}
}

// send runs one request through both bands and returns the response sent to
// the bouncer with every event emitted for it.
func (h *rateLimitHarness) send(clientIP string, session string) (appsec.AppsecTempResponse, []pipeline.Event) {
	h.t.Helper()

	httpReq := &http.Request{Host: "example.com", Header: http.Header{}}
	if session != "" {
		httpReq.Header.Set("X-Session", session)
	}

	req := appsec.ParsedRequest{
		ClientIP:        clientIP,
		RemoteAddr:      clientIP,
		Method:          "GET",
		URI:             "/login",
		UUID:            uuid.NewString(),
		AppsecEngine:    h.engine,
		HTTPRequest:     httpReq,
		ResponseChannel: make(chan appsec.AppsecTempResponse, 1),
	}

	h.runner.handleRequest(h.t.Context(), &req)

	var events []pipeline.Event

	for draining := true; draining; {
		select {
		case e := <-h.out:
			events = append(events, e)
		default:
			draining = false
		}
	}

	return <-req.ResponseChannel, events
}

func rateLimitEvents(events []pipeline.Event) (logs, alerts []pipeline.Event) {
	for _, e := range events {
		switch {
		case e.Type == pipeline.APPSEC:
			alerts = append(alerts, e)
		case e.Parsed["source"] == appsec.SourceRateLimit:
			logs = append(logs, e)
		}
	}

	return logs, alerts
}

func requireAllowed(t *testing.T, resp appsec.AppsecTempResponse, events []pipeline.Event) {
	t.Helper()
	require.False(t, resp.InBandInterrupt)
	require.Equal(t, appsec.AllowRemediation, resp.Action)
	require.Empty(t, events)
}

func requireLimited(t *testing.T, resp appsec.AppsecTempResponse) {
	t.Helper()
	require.True(t, resp.InBandInterrupt)
	require.Equal(t, appsec.BanRemediation, resp.Action)
	require.Equal(t, http.StatusTooManyRequests, resp.UserHTTPResponseCode)
	require.Equal(t, http.StatusForbidden, resp.BouncerHTTPResponseCode)
}

func TestRateLimitByIP(t *testing.T) {
	// Common pre_eval also runs out-of-band: if that pass spent a token, the
	// second request would already be limited.
	h := newRateLimitHarness(t, appsec.Hook{Apply: []string{`RateLimit("login", "2/m")`}})

	for range 2 {
		resp, events := h.send("1.2.3.4", "")
		requireAllowed(t, resp, events)
	}

	resp, events := h.send("1.2.3.4", "")
	requireLimited(t, resp)

	logs, alerts := rateLimitEvents(events)
	require.Len(t, events, 2, "only the rate limit event and alert, no WAF event")
	require.Len(t, logs, 1)
	require.False(t, logs[0].Appsec.HasInBandMatches)
	require.Equal(t, "login", logs[0].Parsed["rate_limit_key"])
	require.Equal(t, "2/m", logs[0].Parsed["rate_limit"])

	require.Len(t, alerts, 1)
	alert := alerts[0].Overflow.Alert
	require.Equal(t, "rate limit exceeded", *alert.Scenario)
	require.Equal(t, "1.2.3.4", alert.Source.IP)

	meta := map[string]string{}
	for _, m := range alert.Meta {
		meta[m.Key] = m.Value
	}

	require.Equal(t, `["login"]`, meta["rate_limit_key"])
	require.Equal(t, `["2/m"]`, meta["rate_limit"])

	status, body := h.runner.AppsecRuntime.GenerateResponse(resp, log.NewEntry(log.New()))
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, http.StatusTooManyRequests, body.HTTPStatus)
	require.Equal(t, appsec.BanRemediation, body.Action)

	// Still limited: an event for every rejection, but no second alert.
	resp, events = h.send("1.2.3.4", "")
	requireLimited(t, resp)

	logs, alerts = rateLimitEvents(events)
	require.Len(t, logs, 1)
	require.Empty(t, alerts)

	resp, events = h.send("5.6.7.8", "")
	requireAllowed(t, resp, events)

	labels := []string{"", h.engine, "login"}
	require.InDelta(t, 2, testutil.ToFloat64(metrics.AppsecRateLimited.WithLabelValues(labels...)), 0)
	require.InDelta(t, 2, testutil.ToFloat64(metrics.AppsecRateLimiters.WithLabelValues(h.engine, "login")), 0)
}

func TestRateLimitBySourceValue(t *testing.T) {
	h := newRateLimitHarness(t, appsec.Hook{Apply: []string{`RateLimit("api", "1/m", req.Header.Get("X-Session"))`}})

	resp, events := h.send("1.1.1.1", "s1")
	requireAllowed(t, resp, events)

	// Keyed on the session, not the IP.
	resp, _ = h.send("2.2.2.2", "s1")
	requireLimited(t, resp)

	resp, events = h.send("1.1.1.1", "s2")
	requireAllowed(t, resp, events)

	// No session: falls back to the IP, which has a budget of its own.
	resp, events = h.send("1.1.1.1", "")
	requireAllowed(t, resp, events)

	// A session spelling an IP must not spend that IP's budget...
	resp, events = h.send("9.9.9.9", "3.3.3.3")
	requireAllowed(t, resp, events)

	resp, events = h.send("3.3.3.3", "")
	requireAllowed(t, resp, events)

	// ...and the IP fallback is limited like any other source.
	resp, _ = h.send("1.1.1.1", "")
	requireLimited(t, resp)
}
