package appsecacquisition

import (
	"net/url"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

/*
 Input:
  - set of rules, directly in yaml ? or using our struct [x] ?
  - appsec.ParsedRequest
 Process:
  - Compile rule
  - Load and start wap
 Expected:
  - waf starting or error
  - comparison on generated events (asserts)
*/

type appsecRuleTest struct {
	name             string
	expected_load_ok bool
	inband_rules     []appsec_rule.CustomRule
	outofband_rules  []appsec_rule.CustomRule
	on_load          []appsec.Hook
	pre_eval         []appsec.Hook
	post_eval        []appsec.Hook
	on_match         []appsec.Hook
	input_request    appsec.ParsedRequest
	output_asserts   func(events []types.Event, responses []appsec.AppsecTempResponse)
}

func TestAppsecOnMatchHooks(t *testing.T) {
	tests := []appsecRuleTest{
		{
			name:             "Basic on_load hook to disable rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetReturnCode(413)"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 2, len(events), "expect no event")
				require.Equal(t, types.LOG, events[0].Type, "Expected log event")
				require.Equal(t, types.APPSEC, events[1].Type, "Expected appsec event")
				require.Equal(t, 1, len(responses), "expect response")
				require.Equal(t, 413, responses[0].HTTPResponseCode, "http return code should be 413")
			},
		},
		{
			name:             "Basic on_load hook to disable rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			on_match: []appsec.Hook{
				{Filter: "IsInBand == false", Apply: []string{"SetReturnCode(413)"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 2, len(events), "expect no event")
				require.Equal(t, types.LOG, events[0].Type, "Expected log event")
				require.Equal(t, types.APPSEC, events[1].Type, "Expected appsec event")
				require.Equal(t, 1, len(responses), "expect response")
				require.Equal(t, 403, responses[0].HTTPResponseCode, "http return code should be 403")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}

func TestAppsecPreEvalHooks(t *testing.T) {
	/*
	 [x] basic working hook
	 [x] basic failing hook
	 [ ] test the "OnSuccess" feature
	 [ ] test multiple competing hooks
	 [ ] test the variety of helpers
	*/
	tests := []appsecRuleTest{
		{
			name:             "Basic on_load hook to disable rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Filter: "1 ==1", Apply: []string{"RemoveInBandRuleByName('rule1')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 0, len(events), "expect no event")
				require.Equal(t, 1, len(responses), "expect response")
				require.Equal(t, false, responses[0].InBandInterrupt, "expect no inband interrupt")
				require.Equal(t, false, responses[0].OutOfBandInterrupt, "expect no outband interrupt")
			},
		},
		{
			name:             "Basic on_load fails to disable rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Filter: "1 ==2", Apply: []string{"RemoveInBandRuleByName('rule1')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 2, len(events), "Expected 2 event")
				require.Equal(t, types.LOG, events[0].Type, "Expected log event")
				require.Equal(t, true, events[0].Appsec.HasInBandMatches, "Expected inband match")
				require.Equal(t, 1, len(events[0].Appsec.MatchedRules), "Expected 1 rule match")
				require.Equal(t, "rule1", events[0].Appsec.MatchedRules[0]["msg"], " rule name")
				require.Equal(t, types.APPSEC, events[1].Type, "Expected appsec event")
				require.Equal(t, 1, len(responses), "expect response")
				require.Equal(t, true, responses[0].InBandInterrupt, "expect no inband interrupt")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}
func TestAppsecRuleMatches(t *testing.T) {

	/*
		[x] basic matching rule
		[x] basic non-matching rule
		[ ] test the transformation
		[ ] ?
	*/
	tests := []appsecRuleTest{
		{
			name:             "Basic matching rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 2, len(events), "Expected 2 event")
				require.Equal(t, types.LOG, events[0].Type, "Expected log event")
				require.Equal(t, true, events[0].Appsec.HasInBandMatches, "Expected inband match")
				require.Equal(t, 1, len(events[0].Appsec.MatchedRules), "Expected 1 rule match")
				require.Equal(t, "rule1", events[0].Appsec.MatchedRules[0]["msg"], " rule name")
				require.Equal(t, types.APPSEC, events[1].Type, "Expected appsec event")
				require.Equal(t, 1, len(responses), "Expected 1 response")
				require.Equal(t, true, responses[0].InBandInterrupt, "Expected deny action")
			},
		},
		{
			name:             "Basic non-matching rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"tutu"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Equal(t, 0, len(events))
				require.Equal(t, 1, len(responses))
				require.Equal(t, false, responses[0].InBandInterrupt)
				require.Equal(t, false, responses[0].OutOfBandInterrupt)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}

func loadAppSecEngine(test appsecRuleTest, t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	inbandRules := []string{}
	outofbandRules := []string{}
	InChan := make(chan appsec.ParsedRequest)
	OutChan := make(chan types.Event)

	logger := log.WithFields(log.Fields{"test": test.name})

	//build rules
	for ridx, rule := range test.inband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.inband_rules), test.name, err)
		}
		inbandRules = append(inbandRules, strRule)

	}
	for ridx, rule := range test.outofband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.outofband_rules), test.name, err)
		}
		outofbandRules = append(outofbandRules, strRule)
	}

	appsecCfg := appsec.AppsecConfig{Logger: logger, OnLoad: test.on_load, PreEval: test.pre_eval, PostEval: test.post_eval, OnMatch: test.on_match}
	AppsecRuntime, err := appsecCfg.Build()
	if err != nil {
		t.Fatalf("unable to build appsec runtime : %s", err)
	}
	AppsecRuntime.InBandRules = []appsec.AppsecCollection{{Rules: inbandRules}}
	AppsecRuntime.OutOfBandRules = []appsec.AppsecCollection{{Rules: outofbandRules}}
	appsecRunnerUUID := uuid.New().String()
	//we copy AppsecRutime for each runner
	wrt := *AppsecRuntime
	wrt.Logger = logger
	runner := AppsecRunner{
		inChan:        InChan,
		UUID:          appsecRunnerUUID,
		logger:        logger,
		AppsecRuntime: &wrt,
		Labels:        map[string]string{"foo": "bar"},
		outChan:       OutChan,
	}
	err = runner.Init("/tmp/")
	if err != nil {
		t.Fatalf("unable to initialize runner : %s", err)
	}

	input := test.input_request
	input.ResponseChannel = make(chan appsec.AppsecTempResponse)
	OutputEvents := make([]types.Event, 0)
	OutputResponses := make([]appsec.AppsecTempResponse, 0)
	go func() {
		for {
			//log.Printf("reading from %p", input.ResponseChannel)
			out := <-input.ResponseChannel
			OutputResponses = append(OutputResponses, out)
			//log.Errorf("response -> %s", spew.Sdump(out))
		}
	}()
	go func() {
		for {
			out := <-OutChan
			OutputEvents = append(OutputEvents, out)
			//log.Errorf("outchan -> %s", spew.Sdump(out))
		}
	}()

	runner.handleRequest(&input)
	time.Sleep(50 * time.Millisecond)
	log.Infof("events : %s", spew.Sdump(OutputEvents))
	log.Infof("responses : %s", spew.Sdump(OutputResponses))
	test.output_asserts(OutputEvents, OutputResponses)

}
