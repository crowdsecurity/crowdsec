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

func TestAppsecBodySize(t *testing.T) {
	tests := []appsecRuleTest{
		{
			// Same pattern as pre_eval DropRequest: 3 events (APPSEC + LOG inband + LOG outband)
			// because BodySizeExceeded triggers DropRequest in both inband and outband processRequest.
			name:             "body size exceeded – default ban",
			expected_load_ok: true,
			input_request: appsec.ParsedRequest{
				ClientIP:         "1.2.3.4",
				RemoteAddr:       "127.0.0.1",
				Method:           "POST",
				URI:              "/",
				HTTPRequest:      &http.Request{Host: "example.com"},
				BodySizeExceeded: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
				require.Equal(t, 403, responses[0].BouncerHTTPResponseCode)
				require.Len(t, events, 3)
				require.Equal(t, pipeline.APPSEC, events[0].Type)
				require.Equal(t, pipeline.LOG, events[1].Type)
				require.Equal(t, pipeline.LOG, events[2].Type)
				require.True(t, events[1].Appsec.HasInBandMatches)
				require.True(t, events[2].Appsec.HasOutBandMatches)
				require.Equal(t, "request body exceeded maximum allowed size", events[1].Parsed["appsec_drop_reason"])
			},
		},
		{
			name:             "body size exceeded – on_match changes status code",
			expected_load_ok: true,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"SetReturnCode(413)"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:         "1.2.3.4",
				RemoteAddr:       "127.0.0.1",
				Method:           "POST",
				URI:              "/",
				HTTPRequest:      &http.Request{Host: "example.com"},
				BodySizeExceeded: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, 413, responses[0].UserHTTPResponseCode)
				require.Equal(t, 403, responses[0].BouncerHTTPResponseCode)
			},
		},
		{
			name:             "body size exceeded – on_match cancels inband alert and event",
			expected_load_ok: true,
			on_match: []appsec.Hook{
				{Filter: "IsInBand == true", Apply: []string{"CancelAlert()", "CancelEvent()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:         "1.2.3.4",
				RemoteAddr:       "127.0.0.1",
				Method:           "POST",
				URI:              "/",
				HTTPRequest:      &http.Request{Host: "example.com"},
				BodySizeExceeded: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				// Inband alert+event canceled; outband LOG event still fires
				require.Len(t, events, 1)
				require.Equal(t, pipeline.LOG, events[0].Type)
				require.True(t, events[0].Appsec.HasOutBandMatches)
			},
		},
		{
			// Body was truncated to the limit; the matched content is in the kept portion.
			name:             "body truncated (partial) – rule matches on kept content",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"BODY_ARGS"},
					Variables: []string{"payload"},
					Match:     appsec_rule.Match{Type: "contains", Value: "MALICIOUS"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:      "1.2.3.4",
				RemoteAddr:    "127.0.0.1",
				Method:        "POST",
				URI:           "/",
				Headers:       http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				HTTPRequest:   &http.Request{Host: "example.com"},
				Body:          []byte("payload=MALICIOUS"),
				BodyTruncated: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			// Body was truncated; the rule matches content only present in the discarded tail.
			name:             "body truncated (partial) – rule misses content beyond truncation point",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"BODY_ARGS"},
					Variables: []string{"payload"},
					Match:     appsec_rule.Match{Type: "contains", Value: "DANGER"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:      "1.2.3.4",
				RemoteAddr:    "127.0.0.1",
				Method:        "POST",
				URI:           "/",
				Headers:       http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				HTTPRequest:   &http.Request{Host: "example.com"},
				Body:          []byte("payload=safe"),
				BodyTruncated: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
			},
		},
		{
			// Body is nil (allow action): body rules do not fire.
			name:             "body nil (allow action) – body rule does not fire",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"BODY_ARGS"},
					Variables: []string{"payload"},
					Match:     appsec_rule.Match{Type: "contains", Value: "TRIGGER"},
				},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:    "1.2.3.4",
				RemoteAddr:  "127.0.0.1",
				Method:      "POST",
				URI:         "/",
				Headers:     http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				HTTPRequest: &http.Request{Host: "example.com"},
				Body:        nil,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
			},
		},
	}

	runTests(t, tests)
}

func TestAppsecDisableBodyInspection(t *testing.T) {
	tests := []appsecRuleTest{
		{
			name:             "DisableBodyInspection - body rule does not fire",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"BODY_ARGS"},
					Variables: []string{"payload"},
					Match:     appsec_rule.Match{Type: "contains", Value: "MALICIOUS"},
				},
			},
			pre_eval: []appsec.Hook{
				{Filter: "1 == 1", Apply: []string{"DisableBodyInspection()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:    "1.2.3.4",
				RemoteAddr:  "127.0.0.1",
				Method:      "POST",
				URI:         "/",
				Headers:     http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				HTTPRequest: &http.Request{Host: "example.com"},
				Body:        []byte("payload=MALICIOUS"),
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.Empty(t, events)
			},
		},
		{
			name:             "DisableBodyInspection - ARGS rule still fires (phase 2 still evaluated)",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"ARGS"},
					Variables: []string{"foo"},
					Match:     appsec_rule.Match{Type: "regex", Value: "^toto"},
				},
			},
			pre_eval: []appsec.Hook{
				{Filter: "1 == 1", Apply: []string{"DisableBodyInspection()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:    "1.2.3.4",
				RemoteAddr:  "127.0.0.1",
				Method:      "GET",
				URI:         "/?foo=toto",
				Args:        url.Values{"foo": []string{"toto"}},
				HTTPRequest: &http.Request{Host: "example.com"},
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			name:             "DisableBodyInspection bypasses BodySizeExceeded drop",
			expected_load_ok: true,
			pre_eval: []appsec.Hook{
				{Filter: "1 == 1", Apply: []string{"DisableBodyInspection()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:         "1.2.3.4",
				RemoteAddr:       "127.0.0.1",
				Method:           "POST",
				URI:              "/",
				HTTPRequest:      &http.Request{Host: "example.com"},
				BodySizeExceeded: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.False(t, responses[0].InBandInterrupt)
				require.Empty(t, events)
			},
		},
		{
			name:             "BodySizeExceeded with conditional DisableBodyInspection - still drops when filter does not match",
			expected_load_ok: true,
			pre_eval: []appsec.Hook{
				{Filter: "req.URL.Path startsWith '/upload'", Apply: []string{"DisableBodyInspection()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:         "1.2.3.4",
				RemoteAddr:       "127.0.0.1",
				Method:           "POST",
				URI:              "/api",
				HTTPRequest:      &http.Request{Host: "example.com"},
				BodySizeExceeded: true,
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
		{
			name:             "DisableBodyInspection - conditional filter, body inspected when filter does not match",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:      "rule1",
					Zones:     []string{"BODY_ARGS"},
					Variables: []string{"payload"},
					Match:     appsec_rule.Match{Type: "contains", Value: "MALICIOUS"},
				},
			},
			pre_eval: []appsec.Hook{
				{Filter: "req.URL.Path startsWith '/upload'", Apply: []string{"DisableBodyInspection()"}},
			},
			input_request: appsec.ParsedRequest{
				ClientIP:    "1.2.3.4",
				RemoteAddr:  "127.0.0.1",
				Method:      "POST",
				URI:         "/api",
				Headers:     http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				HTTPRequest: &http.Request{Host: "example.com"},
				Body:        []byte("payload=MALICIOUS"),
			},
			output_asserts: func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
				require.Len(t, responses, 1)
				require.True(t, responses[0].InBandInterrupt)
				require.Equal(t, appsec.BanRemediation, responses[0].Action)
			},
		},
	}

	runTests(t, tests)
}
