package appsecacquisition

import (
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type appsecRuleTest struct {
	name                   string
	expected_load_ok       bool
	inband_rules           []appsec_rule.CustomRule
	outofband_rules        []appsec_rule.CustomRule
	inband_native_rules    []string
	outofband_native_rules []string
	on_load                []appsec.Hook
	pre_eval               []appsec.Hook
	post_eval              []appsec.Hook
	on_match               []appsec.Hook
	BouncerBlockedHTTPCode int
	UserBlockedHTTPCode    int
	UserPassedHTTPCode     int
	DefaultRemediation     string
	DefaultPassAction      string
	input_request          appsec.ParsedRequest
	afterload_asserts      func(runner AppsecRunner)
	output_asserts         func(events []types.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int)
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

	logger := log.WithField("test", test.name)

	//build rules
	for ridx, rule := range test.inband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.inband_rules), test.name, err)
		}
		inbandRules = append(inbandRules, strRule)

	}
	inbandRules = append(inbandRules, test.inband_native_rules...)
	outofbandRules = append(outofbandRules, test.outofband_native_rules...)
	for ridx, rule := range test.outofband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.outofband_rules), test.name, err)
		}
		outofbandRules = append(outofbandRules, strRule)
	}

	appsecCfg := appsec.AppsecConfig{Logger: logger,
		OnLoad:                 test.on_load,
		PreEval:                test.pre_eval,
		PostEval:               test.post_eval,
		OnMatch:                test.on_match,
		BouncerBlockedHTTPCode: test.BouncerBlockedHTTPCode,
		UserBlockedHTTPCode:    test.UserBlockedHTTPCode,
		UserPassedHTTPCode:     test.UserPassedHTTPCode,
		DefaultRemediation:     test.DefaultRemediation,
		DefaultPassAction:      test.DefaultPassAction}
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
		if !test.expected_load_ok {
			return
		}
		t.Fatalf("unable to initialize runner : %s", err)
	}
	if !test.expected_load_ok {
		t.Fatalf("expected load to fail but it didn't")
	}

	if test.afterload_asserts != nil {
		//afterload asserts are just to evaluate the state of the runner after the rules have been loaded
		//if it's present, don't try to process requests
		test.afterload_asserts(runner)
		return
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

	http_status, appsecResponse := AppsecRuntime.GenerateResponse(OutputResponses[0], logger)
	log.Infof("events : %s", spew.Sdump(OutputEvents))
	log.Infof("responses : %s", spew.Sdump(OutputResponses))
	test.output_asserts(OutputEvents, OutputResponses, appsecResponse, http_status)
}
