package appsecacquisition

import (
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
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
			logger := log.WithField("test", tc.name)

			rt, err := (&appsec.AppsecConfig{Logger: logger}).Build(t.Context(), &cwhub.Hub{})
			require.NoError(t, err)

			var rules []string
			for i, rule := range tc.oobRules {
				strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name, "test-rule", i)
				require.NoError(t, err)
				rules = append(rules, strRule)
			}

			rt.OutOfBandRules = []appsec.AppsecCollection{{Rules: rules}}
			if len(rules) == 0 {
				rt.OutOfBandRules = nil
			}

			outChan := make(chan pipeline.Event, 16)
			rt.OutChan = outChan

			inChan := make(chan appsec.ParsedRequest)
			oobChan := make(chan *outOfBandJob, tc.queueSize)
			newRunner := func() AppsecRunner {
				return AppsecRunner{inChan: inChan, outOfBandChan: oobChan, logger: logger, AppsecRuntime: rt}
			}

			inBand := newRunner()
			require.NoError(t, inBand.InitInBand(t.TempDir()))

			outOfBand := newRunner()
			require.NoError(t, outOfBand.InitOutOfBand(t.TempDir()))

			engine := t.Name()
			dropped := metrics.AppsecOutOfBandDropped.With(prometheus.Labels{"source": "1.2.3.4", "appsec_engine": engine})

			tb := tomb.Tomb{}
			tb.Go(func() error { return inBand.Run(t.Context(), &tb) })

			// The out-of-band runner isn't started yet: every response must
			// still come back.
			for range tc.requests {
				req := appsec.ParsedRequest{
					RemoteAddr:           "1.2.3.4",
					RemoteAddrNormalized: "1.2.3.4",
					Method:               "GET",
					URI:                  "/",
					Args:                 url.Values{"foo": []string{"toto"}},
					HTTPRequest:          &http.Request{Host: "example.com"},
					AppsecEngine:         engine,
					ResponseChannel:      make(chan appsec.AppsecTempResponse, 1),
				}

				select {
				case inChan <- req:
				case <-time.After(5 * time.Second):
					t.Fatal("in-band runner didn't accept the request")
				}

				select {
				case <-req.ResponseChannel:
				case <-time.After(5 * time.Second):
					t.Fatal("no in-band response")
				}
			}

			require.Eventually(t, func() bool {
				return testutil.ToFloat64(dropped) == tc.dropped && len(oobChan) == tc.evaluated
			}, 5*time.Second, 10*time.Millisecond)
			require.Empty(t, outChan)

			tb.Go(func() error { return outOfBand.RunOutOfBand(t.Context(), &tb) })

			require.Eventually(t, func() bool {
				return len(oobChan) == 0 && len(outChan) == tc.evaluated
			}, 5*time.Second, 10*time.Millisecond)

			tb.Kill(nil)
			require.NoError(t, tb.Wait())
		})
	}
}
