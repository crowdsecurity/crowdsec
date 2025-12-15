package appsecacquisition

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
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
	output_asserts         func(events []pipeline.Event, responses []appsec.AppsecTempResponse, appsecResponse appsec.BodyResponse, statusCode int)
}

func setupLapi() (*http.ServeMux, string, func()) {
	return setupWithPrefix("v1")
}

func setupWithPrefix(urlPrefix string) (*http.ServeMux, string, func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux := http.NewServeMux()
	baseURLPath := "/" + urlPrefix

	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}

func loadAppSecEngine(test appsecRuleTest, t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	inbandRules := []string{}
	nativeInbandRules := []string{}
	outofbandRules := []string{}
	nativeOutofbandRules := []string{}
	InChan := make(chan appsec.ParsedRequest)
	OutChan := make(chan pipeline.Event)

	logger := log.WithField("test", test.name)

	//build rules
	for ridx, rule := range test.inband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name, "test-rule")
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.inband_rules), test.name, err)
		}
		inbandRules = append(inbandRules, strRule)
	}

	nativeInbandRules = append(nativeInbandRules, test.inband_native_rules...)
	nativeOutofbandRules = append(nativeOutofbandRules, test.outofband_native_rules...)
	for ridx, rule := range test.outofband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name, "test-rule")
		if err != nil {
			t.Fatalf("failed compilation of rule %d/%d of %s : %s", ridx, len(test.outofband_rules), test.name, err)
		}
		outofbandRules = append(outofbandRules, strRule)
	}

	appsecCfg := appsec.AppsecConfig{
		Logger:                 logger,
		OnLoad:                 test.on_load,
		PreEval:                test.pre_eval,
		PostEval:               test.post_eval,
		OnMatch:                test.on_match,
		BouncerBlockedHTTPCode: test.BouncerBlockedHTTPCode,
		UserBlockedHTTPCode:    test.UserBlockedHTTPCode,
		UserPassedHTTPCode:     test.UserPassedHTTPCode,
		DefaultRemediation:     test.DefaultRemediation,
		DefaultPassAction:      test.DefaultPassAction,
	}

	hub := cwhub.Hub{}
	AppsecRuntime, err := appsecCfg.Build(&hub)
	if err != nil {
		t.Fatalf("unable to build appsec runtime : %s", err)
	}
	AppsecRuntime.InBandRules = []appsec.AppsecCollection{{Rules: inbandRules, NativeRules: nativeInbandRules}}
	AppsecRuntime.OutOfBandRules = []appsec.AppsecCollection{{Rules: outofbandRules, NativeRules: nativeOutofbandRules}}
	appsecRunnerUUID := uuid.New().String()
	//we copy AppsecRutime for each runner
	wrt := *AppsecRuntime
	wrt.Logger = logger

	mux, urlx, teardown := setupLapi()
	defer teardown()

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client := apiclient.NewClient(&apiclient.Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/allowlists", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("with_content") != "true" {
			t.Error("with_content not set")
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`[{"allowlist_id":"xxxx","console_managed":false,"created_at":"2025-02-11T14:47:35.839Z","description":"test_desc2",
		"items":[{"created_at":"2025-02-12T09:32:53.939Z","description":"sdfsdaf","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.3.2"},
		{"created_at":"2025-02-12T09:32:53.939Z","description":"sdfsdaf","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.4.0/24"}]}]`))
		assert.NoError(t, err)
	})

	allowlistClient := allowlists.NewAppsecAllowlist(logger)

	err = allowlistClient.Start(t.Context(), client)
	require.NoError(t, err)
	runner := AppsecRunner{
		inChan:                 InChan,
		UUID:                   appsecRunnerUUID,
		logger:                 logger,
		AppsecRuntime:          &wrt,
		Labels:                 map[string]string{"foo": "bar"},
		outChan:                OutChan,
		appsecAllowlistsClient: allowlistClient,
	}

	err = runner.Init("/tmp/")
	if err != nil {
		if !test.expected_load_ok {
			return
		}
		t.Fatalf("unable to initialize runner : %s", err)
	}
	if !test.expected_load_ok {
		t.Fatal("expected load to fail but it didn't")
	}

	if test.afterload_asserts != nil {
		//afterload asserts are just to evaluate the state of the runner after the rules have been loaded
		//if it's present, don't try to process requests
		test.afterload_asserts(runner)
		return
	}

	input := test.input_request
	input.ResponseChannel = make(chan appsec.AppsecTempResponse)

	// collect both responses and events until no activity for idleDuration
	idleDuration := 50 * time.Millisecond
	idle := time.NewTimer(idleDuration)
	defer idle.Stop()

	// when we receive something, drain and restart the idle timer
	reset := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(idleDuration)
	}

	responses :=[]appsec.AppsecTempResponse{}
	events := []pipeline.Event{}

	done := make(chan struct{})

	// collect in a goroutine so a receiver is ready
	go func() {
		for {
			select {
			case r := <-input.ResponseChannel:
				responses = append(responses, r)
				reset()
			case e := <-OutChan:
				events = append(events, e)
				reset()
			case <-idle.C:
				close(done)
				return
			}
		}
	}()

	runner.handleRequest(&input)

	// wait for the idle duration
	<-done

	require.NotEmpty(t, responses)
	httpStatus, appsecResponse := AppsecRuntime.GenerateResponse(responses[0], logger)
	log.Infof("events : %s", spew.Sdump(events))
	log.Infof("responses : %s", spew.Sdump(responses))
	test.output_asserts(events, responses, appsecResponse, httpStatus)
}
