package appsecacquisition

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, 403, responses[0].BouncerHTTPResponseCode)
				require.Equal(t, 403, responses[0].UserHTTPResponseCode)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, 403, responses[0].BouncerHTTPResponseCode)
				require.Equal(t, 413, responses[0].UserHTTPResponseCode)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to a non standard one (log)",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, "log", responses[0].Action)
				require.Equal(t, 403, responses[0].BouncerHTTPResponseCode)
				require.Equal(t, 403, responses[0].UserHTTPResponseCode)
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Len(t, responses, 1)
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
			},
		},
		{
			name:             "on_match: change action to another standard one (ban)",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('ban')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				//note: SetAction normalizes deny, ban and block to ban
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				//note: SetAction normalizes deny, ban and block to ban
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 1)
				require.Equal(t, types.LOG, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 1)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			name:             "on_match: on_success break",
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
				{Filter: "IsInBand == true", Apply: []string{"CancelEvent()"}, OnSuccess: "break"},
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 1)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			name:             "on_match: on_success continue",
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
				{Filter: "IsInBand == true", Apply: []string{"CancelEvent()"}, OnSuccess: "continue"},
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 1)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Len(t, responses, 1)
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
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
	tests := []appsecRuleTest{
		{
			name:             "Basic pre_eval hook to disable inband rule",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "Basic pre_eval fails to disable rule",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
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
			name:             "pre_eval : disable inband by tag",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "pre_eval : disable inband by ID",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "pre_eval : disable inband by name",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "pre_eval : outofband default behavior",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
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
			name:             "pre_eval : set remediation by tag",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
			},
		},
		{
			name:             "pre_eval : set remediation by name",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
			},
		},
		{
			name:             "pre_eval : set remediation by ID",
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar", responses[0].Action)
				require.Equal(t, "foobar", appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "pre_eval : on_success continue",
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
				{Filter: "1==1", Apply: []string{"SetRemediationByName('rulez', 'foobar')"}, OnSuccess: "continue"},
				{Filter: "1==1", Apply: []string{"SetRemediationByName('rulez', 'foobar2')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Len(t, responses, 1)
				require.Equal(t, "foobar2", responses[0].Action)
			},
		},
		{
			name:             "pre_eval : on_success break",
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
				{Filter: "1==1", Apply: []string{"SetRemediationByName('rulez', 'foobar')"}, OnSuccess: "break"},
				{Filter: "1==1", Apply: []string{"SetRemediationByName('rulez', 'foobar2')"}},
			},
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
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

func TestAppsecRemediationConfigHooks(t *testing.T) {
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
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "SetRemediation",
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
			on_match: []appsec.Hook{{Apply: []string{"SetRemediation('captcha')"}}}, //rule ID is generated at runtime. If you change rule, it will break the test (:

			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "SetRemediation",
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
			on_match: []appsec.Hook{{Apply: []string{"SetReturnCode(418)"}}}, //rule ID is generated at runtime. If you change rule, it will break the test (:

			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}

func TestOnMatchRemediationHooks(t *testing.T) {
	tests := []appsecRuleTest{
		{
			name:             "set remediation to allow with on_match hook",
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
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('allow')"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "set remediation to captcha + custom user code with on_match hook",
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
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: appsec.AllowRemediation,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')", "SetReturnCode(418)"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				spew.Dump(responses)
				spew.Dump(appsecResponse)

				log.Errorf("http status : %d", statusCode)
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
				require.Equal(t, http.StatusForbidden, statusCode)
			},
		},
		{
			name:             "on_match: on_success break",
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
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: appsec.AllowRemediation,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')", "SetReturnCode(418)"}, OnSuccess: "break"},
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('ban')"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				spew.Dump(responses)
				spew.Dump(appsecResponse)

				log.Errorf("http status : %d", statusCode)
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
				require.Equal(t, http.StatusForbidden, statusCode)
			},
		},
		{
			name:             "on_match: on_success continue",
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
			input_request: appsec.ParsedRequest{
				RemoteAddr: "1.2.3.4",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: appsec.AllowRemediation,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')", "SetReturnCode(418)"}, OnSuccess: "continue"},
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('ban')"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				spew.Dump(responses)
				spew.Dump(appsecResponse)

				log.Errorf("http status : %d", statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
				require.Equal(t, http.StatusForbidden, statusCode)
			},
		},
		{
			name:             "on_match: allowlisted IP",
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
			input_request: appsec.ParsedRequest{
				ClientIP:   "5.4.3.2",
				RemoteAddr: "5.4.3.2",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: appsec.AllowRemediation,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')", "SetReturnCode(418)"}, OnSuccess: "continue"},
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('ban')"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				spew.Dump(responses)
				spew.Dump(appsecResponse)

				log.Errorf("http status : %d", statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
				require.Equal(t, http.StatusOK, statusCode)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}
