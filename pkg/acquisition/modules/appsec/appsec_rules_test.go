package appsecacquisition

import (
	"net/http"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestAppsecRuleMatches(t *testing.T) {
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
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
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
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"tutu"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.False(t, responses[0].OutOfBandInterrupt)
			},
		},
		{
			name:             "default remediation to allow",
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
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: "allow",
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "default remediation to captcha",
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
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			DefaultRemediation: "captcha",
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "no default remediation / custom user HTTP code",
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
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"toto"}},
			},
			UserBlockedHTTPCode: 418,
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "no match but try to set remediation to captcha with on_match hook",
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
				{Filter: "IsInBand == true", Apply: []string{"SetRemediation('captcha')"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"bla"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
			},
		},
		{
			name:             "no match but try to set user HTTP code with on_match hook",
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
				{Filter: "IsInBand == true", Apply: []string{"SetReturnCode(418)"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"bla"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
			},
		},
		{
			name:             "no match but try to set  remediation with pre_eval hook",
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
			pre_eval: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetRemediationByName('rule42', 'captcha')"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Args:       url.Values{"foo": []string{"bla"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Empty(t, events)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
			},
		},
		{
			name:             "Basic matching in cookies",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"COOKIES"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Headers:    http.Header{"Cookie": []string{"foo=toto"}},
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
			name:             "Basic matching in all cookies",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"COOKIES"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^tutu"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Headers:    http.Header{"Cookie": []string{"foo=toto; bar=tutu"}},
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
			name:             "Basic matching in cookie name",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"COOKIES_NAMES"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^tutu"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Headers:    http.Header{"Cookie": []string{"bar=tutu; tututata=toto"}},
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
			name:             "Basic matching in multipart file name",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"FILES"},
					Match:     appsec_rule.Match{Type: "regex", Value: "\\.php$"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Headers:    http.Header{"Content-Type": []string{"multipart/form-data; boundary=boundary"}},
				Body: []byte(`
--boundary
Content-Disposition: form-data; name="foo"; filename="bar.php"
Content-Type: application/octet-stream

toto
--boundary--`),
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
			name:             "Basic matching IP address",
			expected_load_ok: true,
			inband_native_rules: []string{
				"SecRule REMOTE_ADDR \"@ipMatch 1.2.3.4\" \"id:1,phase:1,log,deny,msg: 'block ip'\"",
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/urllll",
				Headers:    http.Header{"Content-Type": []string{"multipart/form-data; boundary=boundary"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)

				require.Equal(t, types.LOG, events[1].Type)
				require.True(t, events[1].Appsec.HasInBandMatches)
				require.Len(t, events[1].Appsec.MatchedRules, 1)
				require.Equal(t, "block ip", events[1].Appsec.MatchedRules[0]["msg"])

				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}

func TestAppsecRuleTransforms(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	tests := []appsecRuleTest{
		{
			name:             "Basic matching rule",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"URI"},
					Match: appsec_rule.Match{Type: "equals", Value: "/toto"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/toto",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "lowercase",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"URI"},
					Match:     appsec_rule.Match{Type: "equals", Value: "/toto"},
					Transform: []string{"lowercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/TOTO",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "uppercase",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"URI"},
					Match:     appsec_rule.Match{Type: "equals", Value: "/TOTO"},
					Transform: []string{"uppercase"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/toto",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "b64decode",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "equals", Value: "toto"},
					Transform: []string{"b64decode"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/?foo=dG90bw",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "b64decode with extra padding",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "equals", Value: "toto"},
					Transform: []string{"b64decode"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/?foo=dG90bw===",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "length",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "gte", Value: "3"},
					Transform: []string{"length"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/?foo=toto",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "urldecode",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "equals", Value: "BB/A"},
					Transform: []string{"urldecode"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/?foo=%42%42%2F%41",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "trim",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "equals", Value: "BB/A"},
					Transform: []string{"urldecode", "trim"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/?foo=%20%20%42%42%2F%41%20%20",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}

func TestAppsecRuleZones(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	tests := []appsecRuleTest{
		{
			name:             "rule: ARGS",
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
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/foobar?something=toto&foobar=smth",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: ARGS_NAMES",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"ARGS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/foobar?something=toto&foobar=smth",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule2", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: BODY_ARGS",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"BODY_ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"BODY_ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Body:       []byte("smth=toto&foobar=other"),
				Headers:    http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: BODY_ARGS_NAMES",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"BODY_ARGS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"BODY_ARGS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Body:       []byte("smth=toto&foobar=other"),
				Headers:    http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule2", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: HEADERS",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"HEADERS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"HEADERS"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Headers:    http.Header{"foobar": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: HEADERS_NAMES",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"HEADERS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"HEADERS_NAMES"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Headers:    http.Header{"foobar": []string{"toto"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule2", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: METHOD",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"METHOD"},
					Match: appsec_rule.Match{Type: "equals", Value: "GET"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: PROTOCOL",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"PROTOCOL"},
					Match: appsec_rule.Match{Type: "contains", Value: "3.1"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Proto:      "HTTP/3.1",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: URI",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"URI"},
					Match: appsec_rule.Match{Type: "equals", Value: "/foobar"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/foobar",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: URI_FULL",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"URI_FULL"},
					Match: appsec_rule.Match{Type: "equals", Value: "/foobar?a=b"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/foobar?a=b",
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
		{
			name:             "rule: RAW_BODY",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"RAW_BODY"},
					Match: appsec_rule.Match{Type: "equals", Value: "foobar=42421"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:   "1.2.3.4",
				RemoteAddr: "127.0.0.1",
				Method:     "GET",
				URI:        "/",
				Body:       []byte("foobar=42421"),
				Headers:    http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
			},
			output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, events, 2)
				require.Equal(t, types.APPSEC, events[0].Type)
				require.Equal(t, types.LOG, events[1].Type)
				require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}
