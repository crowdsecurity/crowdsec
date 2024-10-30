//go:build windows

package appsecacquisition

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestAppsecRuleTransformsWindows(t *testing.T) {

	log.SetLevel(log.TraceLevel)
	tests := []appsecRuleTest{
		// {
		// 	name:             "normalizepath",
		// 	expected_load_ok: true,
		// 	inband_rules: []appsec_rule.CustomRule{
		// 		{
		// 			Name:      "rule1",
		// 			Zones:     []string{"ARGS"},
		// 			Variables: []string{"foo"},
		// 			Match:     appsec_rule.Match{Type: "equals", Value: "b/c"},
		// 			Transform: []string{"normalizepath"},
		// 		},
		// 	},
		// 	input_request: appsec.ParsedRequest{
		// 		RemoteAddr: "1.2.3.4",
		// 		Method:     "GET",
		// 		URI:        "/?foo=a/../b/c",
		// 	},
		// 	output_asserts: func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int) {
		// 		require.Len(t, events, 2)
		// 		require.Equal(t, types.APPSEC, events[0].Type)
		// 		require.Equal(t, types.LOG, events[1].Type)
		// 		require.Equal(t, "rule1", events[1].Appsec.MatchedRules[0]["msg"])
		// 	},
		// },
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}
