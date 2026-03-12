package appsecacquisition

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestAppsecDefaultPassRemediation(t *testing.T) {
	tests := []appsecRuleTest{
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/",
				Args:        url.Values{"foo": []string{"tutu"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "DefaultPassAction: pass",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/",
				Args:        url.Values{"foo": []string{"tutu"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			DefaultPassAction: "allow",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "DefaultPassAction: captcha",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/",
				Args:        url.Values{"foo": []string{"tutu"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			DefaultPassAction: "captcha",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode) //@tko: body is captcha, but as it's 200, captcha won't be showed to user
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "DefaultPassHTTPCode: 200",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/",
				Args:        url.Values{"foo": []string{"tutu"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			UserPassedHTTPCode: 200,
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusOK, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "DefaultPassHTTPCode: 200",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/",
				Args:        url.Values{"foo": []string{"tutu"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			UserPassedHTTPCode: 418,
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.AllowRemediation, responses[0].Action)
				require.Equal(t, http.StatusOK, statusCode)
				require.Equal(t, appsec.AllowRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
			},
		},
	}

	runTests(t, tests)
}

func TestAppsecDefaultRemediation(t *testing.T) {
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "default remediation to ban (default)",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			DefaultRemediation: "ban",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			DefaultRemediation: "allow",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			DefaultRemediation: "captcha",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.CaptchaRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.CaptchaRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusForbidden, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "custom user HTTP code",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			UserBlockedHTTPCode: 418,
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, appsec.BanRemediation, appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
			},
		},
		{
			name:             "custom remediation + HTTP code",
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
				RemoteAddr:  "1.2.3.4",
				Method:      "GET",
				URI:         "/urllll",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			UserBlockedHTTPCode: 418,
			DefaultRemediation:  "foobar",
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Equal(t, "foobar", responses[0].Action)
				require.Equal(t, http.StatusForbidden, statusCode)
				require.Equal(t, "foobar", appsecResponse.Action)
				require.Equal(t, http.StatusTeapot, appsecResponse.HTTPStatus)
			},
		},
	}

	runTests(t, tests)
}
