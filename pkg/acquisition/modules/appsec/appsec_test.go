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

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/allowlists"
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
	nativeInbandRules = append(nativeInbandRules, test.inband_native_rules...)
	nativeOutofbandRules = append(nativeOutofbandRules, test.outofband_native_rules...)
	for ridx, rule := range test.outofband_rules {
		strRule, _, err := rule.Convert(appsec_rule.ModsecurityRuleType, rule.Name)
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
	AppsecRuntime, err := appsecCfg.Build()
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

	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/allowlists", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("with_content") != "true" {
			t.Errorf("with_content not set")
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`[{"allowlist_id":"xxxx","console_managed":false,"created_at":"2025-02-11T14:47:35.839Z","description":"test_desc2",
		"items":[{"created_at":"2025-02-12T09:32:53.939Z","description":"sdfsdaf","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.3.2"},
		{"created_at":"2025-02-12T09:32:53.939Z","description":"sdfsdaf","expiration":"0001-01-01T00:00:00.000Z","value":"5.4.4.0/24"}]}]`))
		assert.NoError(t, err)
	})

	allowlistClient := allowlists.NewAppsecAllowlist(client, logger)
	// In real life, allowlists updater is started by the acquisition
	// Do it manually here as we are simulating the appsec itself
	err = allowlistClient.FetchAllowlists()
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
