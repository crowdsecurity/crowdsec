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
Missing tests (wip):
 - GenerateResponse
 - evt.Appsec and it's subobjects and methods
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
			name:             "no rule : check return code",
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
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, 403, responses[0].RemediationComponentHTTPResponseCode)
				require.Equal(t, 403, responses[0].UserHTTPResponseCode)
				require.Equal(t, "ban", responses[0].Action)

			},
		},
		{
			name:             "on_match: change return code",
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
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, 403, responses[0].RemediationComponentHTTPResponseCode)
				require.Equal(t, 413, responses[0].UserHTTPResponseCode)
				require.Equal(t, "ban", responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to another standard one (log)",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('log')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "log", responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to another standard one (allow)",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('allow')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "allow", responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to another standard one (deny/ban/block)",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('deny')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, responses, 1)
				//note: SetAction normalizes deny, ban and block to ban
				require.Equal(t, "ban", responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to another standard one (captcha)",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, responses, 1)
				//note: SetAction normalizes deny, ban and block to ban
				require.Equal(t, "captcha", responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to a non standard one",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('foobar')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
			},
		},
		{
			name:             "on_match: cancel alert",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule42",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true && LogInfo('XX -> %s', evt.Appsec.MatchedRules.GetName())", Apply: []string{"CancelAlert()"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 1)
				require.Equal(t, types.LOG, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "ban", responses[0].Action)
			},
		},
		{
			name:             "on_match: cancel event",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule42",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"CancelEvent()"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 1)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "ban", responses[0].Action)
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
			name:             "Basic on_load hook to disable inband rule",
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
				{Filter: "1 == 1", Apply: []string{"RemoveInBandRuleByName('rule1')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
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
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)

				require.Equal(t, types.LOG, events[1].Type)
				require.True(t, events[1].Appsec.HasInBandMatches)
				require.Len(t, events[1].Appsec.MatchedRules, 1)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])

				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)

			},
		},
		{
			name:             "on_load : disable inband by tag",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"RemoveInBandRuleByTag('crowdsec-rulez')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "on_load : disable inband by ID",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"RemoveInBandRuleByID(1516470898)"}}, //rule ID is generated at runtime. If you change rule, it will break the test (:
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "on_load : disable inband by name",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"RemoveInBandRuleByName('rulez')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "on_load : outofband default behavior",
			expected_load_ok: true,
			outofband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
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
				require.Len(t, events, 1)
				require.Equal(t, types.LOG, events[0].Type)
				require.True(t, events[0].Appsec.HasOutBandMatches)
				require.False(t, events[0].Appsec.HasInBandMatches)
				require.Len(t, events[0].Appsec.MatchedRules, 1)
				require.Equal(t, "rulez", events[0].Appsec.MatchedRules[0]["msg"])
				//maybe surprising, but response won't mention OOB event, as it's sent as soon as the inband phase is over.
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "on_load : set remediation by tag",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"SetRemediationByTag('crowdsec-rulez', 'foobar')"}}, //rule ID is generated at runtime. If you change rule, it will break the test (:
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
			},
		},
		{
			name:             "on_load : set remediation by name",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"SetRemediationByName('rulez', 'foobar')"}}, //rule ID is generated at runtime. If you change rule, it will break the test (:
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
			},
		},
		{
			name:             "on_load : set remediation by ID",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rulez",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			pre_eval: []appsec.Hook{
				{Apply: []string{"SetRemediationByID(1516470898, 'foobar')"}}, //rule ID is generated at runtime. If you change rule, it will break the test (:
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
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
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)

				require.Equal(t, types.LOG, events[1].Type)
				require.True(t, events[1].Appsec.HasInBandMatches)
				require.Len(t, events[1].Appsec.MatchedRules, 1)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])

				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
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
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
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
