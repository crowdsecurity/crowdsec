package appsecacquisition

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestAppsecConflictRuleLoad(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	tests := []appsecRuleTest{
		{
			name:             "simple native rule load",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "id conflict on native rule load",
			expected_load_ok: false,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
			},
		},
		{
			name:             "simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "duplicate rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
	}

	runTests(t, tests)
}

func TestAppsecRuleLoad(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	tests := []appsecRuleTest{
		{
			name:             "simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "simple native rule load",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "simple native rule load (2)",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "multi simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "multi simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "imbricated rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name: "rule1",

					Or: []appsec_rule.CustomRule{
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "toto"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "tutu"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "tata"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "titi"},
						},
					},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 4)
			},
		},
		{
			name:             "invalid inband rule",
			expected_load_ok: false,
			inband_native_rules: []string{
				"this_is_not_a_rule",
			},
		},
		{
			name:             "invalid outofband rule",
			expected_load_ok: false,
			outofband_native_rules: []string{
				"this_is_not_a_rule",
			},
		},
	}

	runTests(t, tests)
}

// AppsecRunner.closeEngine reaches Close through an io.Closer assertion, because
// coraza.WAF doesn't declare Close. If the concrete type ever stops implementing
// it, that assertion turns the whole teardown into a silent no-op.
func TestEngineImplementsCloser(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		`SecRule REQUEST_URI "@rx abc" "id:1,phase:2,deny,log"`))
	require.NoError(t, err)

	closer, ok := waf.(io.Closer)
	require.True(t, ok, "coraza.NewWAF result must implement io.Closer")
	require.NoError(t, closer.Close())
	require.NoError(t, closer.Close(), "Close must be idempotent")
}

// asyncHarness wires an in-band and an out-of-band runner the way
// buildRunners does, without starting them.
type asyncHarness struct {
	inBand, outOfBand AppsecRunner
	inChan            chan appsec.ParsedRequest
	oobChan           chan *outOfBandJob
	outChan           chan pipeline.Event
	engine            string
}

func newAsyncHarness(t *testing.T, cfg appsec.AppsecConfig, inBandRules, oobRules []appsec_rule.CustomRule, queueSize int) *asyncHarness {
	t.Helper()

	rt, err := cfg.Build(t.Context(), &cwhub.Hub{})
	require.NoError(t, err)

	convert := func(custom []appsec_rule.CustomRule) []appsec.AppsecCollection {
		if len(custom) == 0 {
			return nil
		}

		var rules []string
		for i, rule := range custom {
			strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name, "test-rule", i)
			require.NoError(t, err)
			rules = append(rules, strRule)
		}

		return []appsec.AppsecCollection{{Rules: rules}}
	}

	rt.InBandRules = convert(inBandRules)
	rt.OutOfBandRules = convert(oobRules)

	h := &asyncHarness{
		inChan:  make(chan appsec.ParsedRequest),
		oobChan: make(chan *outOfBandJob, queueSize),
		outChan: make(chan pipeline.Event, 16),
		engine:  t.Name(),
	}
	rt.OutChan = h.outChan

	newRunner := func() AppsecRunner {
		return AppsecRunner{inChan: h.inChan, outOfBandChan: h.oobChan, logger: cfg.Logger, AppsecRuntime: rt}
	}

	h.inBand = newRunner()
	require.NoError(t, h.inBand.InitInBand(t.TempDir()))

	h.outOfBand = newRunner()
	require.NoError(t, h.outOfBand.InitOutOfBand(t.TempDir()))

	return h
}

// send pushes a request through the in-band runner and returns the bouncer response.
func (h *asyncHarness) send(t *testing.T, requestUUID string, host string) appsec.AppsecTempResponse {
	t.Helper()

	req := appsec.ParsedRequest{
		UUID:                 requestUUID,
		RemoteAddr:           "1.2.3.4",
		RemoteAddrNormalized: "1.2.3.4",
		Method:               "GET",
		URI:                  "/",
		Args:                 url.Values{"foo": []string{"toto"}},
		HTTPRequest:          &http.Request{Host: host},
		AppsecEngine:         h.engine,
		ResponseChannel:      make(chan appsec.AppsecTempResponse, 1),
	}

	select {
	case h.inChan <- req:
	case <-time.After(5 * time.Second):
		t.Fatal("in-band runner didn't accept the request")
	}

	select {
	case resp := <-req.ResponseChannel:
		return resp
	case <-time.After(5 * time.Second):
		t.Fatal("no in-band response")
	}

	return appsec.AppsecTempResponse{}
}

// In-band runners must answer the bouncer without waiting for out-of-band
// evaluation, and drop it rather than block once the queue is full.
func TestOutOfBandIsAsync(t *testing.T) {
	oobRule := appsec_rule.CustomRule{
		Name:      "rule42",
		Zones:     []string{"ARGS"},
		Variables: []string{"foo"},
		Match:     appsec_rule.Match{Type: "equals", Value: "toto"},
	}

	tests := []struct {
		name      string
		oobRules  []appsec_rule.CustomRule
		queueSize int
		requests  int
		dropped   float64
		evaluated int
	}{
		{name: "queue full drops", oobRules: []appsec_rule.CustomRule{oobRule}, queueSize: 1, requests: 3, dropped: 2, evaluated: 1},
		{name: "queue large enough", oobRules: []appsec_rule.CustomRule{oobRule}, queueSize: 4, requests: 3, dropped: 0, evaluated: 3},
		{name: "nothing queued without out-of-band rules", queueSize: 1, requests: 3, dropped: 0, evaluated: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newAsyncHarness(t, appsec.AppsecConfig{Logger: log.WithField("test", tc.name)}, nil, tc.oobRules, tc.queueSize)
			dropped := metrics.AppsecOutOfBandDropped.With(prometheus.Labels{"source": "1.2.3.4", "appsec_engine": h.engine})

			tb := tomb.Tomb{}
			tb.Go(func() error { return h.inBand.Run(t.Context(), &tb) })

			// The out-of-band runner isn't started yet: every response must
			// still come back.
			for i := range tc.requests {
				h.send(t, fmt.Sprintf("req-%d", i), "example.com")
			}

			require.Eventually(t, func() bool {
				return testutil.ToFloat64(dropped) == tc.dropped && len(h.oobChan) == tc.evaluated
			}, 5*time.Second, 10*time.Millisecond)
			require.Empty(t, h.outChan)

			tb.Go(func() error { return h.outOfBand.RunOutOfBand(t.Context(), &tb) })

			require.Eventually(t, func() bool {
				return len(h.oobChan) == 0 && len(h.outChan) == tc.evaluated
			}, 5*time.Second, 10*time.Millisecond)

			tb.Kill(nil)
			require.NoError(t, tb.Wait())
		})
	}
}

// Hooks log with the request they run for, even when the in-band runner has
// moved on to the next request by the time the out-of-band phase runs.
func TestOutOfBandHookLogsOwnRequest(t *testing.T) {
	logger, logHook := logtest.NewNullLogger()
	logger.SetLevel(log.DebugLevel)

	cfg := appsec.AppsecConfig{
		Logger: logger.WithField("test", t.Name()),
		OutOfBand: &appsec.AppsecPhaseConfig{
			PreEval: []appsec.Hook{{Apply: []string{"RemoveOutBandRuleByID(1)"}}},
		},
	}
	h := newAsyncHarness(t, cfg, nil, nil, 4)

	tb := tomb.Tomb{}
	tb.Go(func() error { return h.inBand.Run(t.Context(), &tb) })

	h.send(t, "req-a", "example.com")
	h.send(t, "req-b", "example.com")

	require.Eventually(t, func() bool { return len(h.oobChan) == 2 }, 5*time.Second, 10*time.Millisecond)

	tb.Go(func() error { return h.outOfBand.RunOutOfBand(t.Context(), &tb) })

	removed := func() []any {
		var uuids []any
		for _, e := range logHook.AllEntries() {
			if strings.HasPrefix(e.Message, "removing outband rule") {
				uuids = append(uuids, e.Data["request_uuid"])
			}
		}
		return uuids
	}

	require.Eventually(t, func() bool { return len(removed()) == 2 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []any{"req-a", "req-b"}, removed())

	tb.Kill(nil)
	require.NoError(t, tb.Wait())
}

// SetRemediationBy* in pre_eval only affects the request it ran for.
func TestPreEvalRemediationIsPerRequest(t *testing.T) {
	rule := appsec_rule.CustomRule{
		Name:      "rule42",
		Zones:     []string{"ARGS"},
		Variables: []string{"foo"},
		Match:     appsec_rule.Match{Type: "equals", Value: "toto"},
	}

	tests := []struct {
		name  string
		apply string
	}{
		{name: "by name", apply: "SetRemediationByName('rule42', 'captcha')"},
		{name: "by tag", apply: "SetRemediationByTag('crowdsec-rule42', 'captcha')"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := appsec.AppsecConfig{
				Logger:             log.WithField("test", t.Name()),
				DefaultRemediation: appsec.BanRemediation,
				PreEval:            []appsec.Hook{{Filter: "req.Host == 'captcha.example.com'", Apply: []string{tc.apply}}},
			}
			h := newAsyncHarness(t, cfg, []appsec_rule.CustomRule{rule}, nil, 1)

			tb := tomb.Tomb{}
			tb.Go(func() error { return h.inBand.Run(t.Context(), &tb) })

			require.Equal(t, appsec.CaptchaRemediation, h.send(t, "req-a", "captcha.example.com").Action)
			require.Equal(t, appsec.BanRemediation, h.send(t, "req-b", "example.com").Action)

			tb.Kill(nil)
			require.NoError(t, tb.Wait())
		})
	}
}
