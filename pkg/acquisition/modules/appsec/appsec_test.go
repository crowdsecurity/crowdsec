package appsecacquisition

import (
	"net/url"
	"testing"

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
	input_request    appsec.ParsedRequest
	output_asserts   func(events []types.Event, responses []appsec.AppsecTempResponse)
}

func TestAppsec(t *testing.T) {

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
				require.Equal(t, len(events), 2, "Expected 2 event")
				require.Equal(t, events[0].Type, types.LOG, "Expected log event")
				require.Equal(t, events[0].Appsec.HasInBandMatches, true, "Expected inband match")
				require.Equal(t, len(events[0].Appsec.MatchedRules), 1, "Expected 1 rule match")
				require.Equal(t, events[0].Appsec.MatchedRules[0]["msg"], "rule1", " rule name")
				require.Equal(t, events[1].Type, types.APPSEC, "Expected appsec event")
				require.Equal(t, len(responses), 1, "Expected 1 response")
				require.Equal(t, responses[0].InBandInterrupt, true, "Expected deny action")
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
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	inbandRules := []string{}
	InChan := make(chan appsec.ParsedRequest)
	OutChan := make(chan types.Event)

	logger := log.WithFields(log.Fields{"test": test.name})

	for ridx, rule := range test.inband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.inband_rules), test.name, err)
		}
		inbandRules = append(inbandRules, strRule)

	}
	appsecCfg := appsec.AppsecConfig{Logger: logger}
	AppsecRuntime, err := appsecCfg.Build()
	if err != nil {
		t.Fatalf("unable to build appsec runtime : %s", err)
	}
	AppsecRuntime.InBandRules = []appsec.AppsecCollection{{Rules: inbandRules}}
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

	log.Infof("events : %s", spew.Sdump(OutputEvents))
	log.Infof("responses : %s", spew.Sdump(OutputResponses))
	test.output_asserts(OutputEvents, OutputResponses)

}
