package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jarcoal/httpmock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func getDBClient(t *testing.T) *database.Client {
	t.Helper()
	dbPath, err := os.CreateTemp("", "*sqlite")
	if err != nil {
		t.Fatal(err)
	}
	dbClient, err := database.NewClient(&csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: dbPath.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return dbClient
}

func getAPIC(t *testing.T) *apic {
	t.Helper()
	dbClient := getDBClient(t)
	return &apic{
		alertToPush:  make(chan []*models.Alert),
		dbClient:     dbClient,
		mu:           sync.Mutex{},
		startup:      true,
		pullTomb:     tomb.Tomb{},
		pushTomb:     tomb.Tomb{},
		metricsTomb:  tomb.Tomb{},
		scenarioList: make([]string, 0),
		consoleConfig: &csconfig.ConsoleConfig{
			ShareManualDecisions:  types.BoolPtr(false),
			ShareTaintedScenarios: types.BoolPtr(false),
			ShareCustomScenarios:  types.BoolPtr(false),
		},
	}
}

func absDiff(a int, b int) (c int) {
	if c = a - b; c < 0 {
		return -1 * c
	}
	return c
}

func assertTotalDecisionCount(t *testing.T, dbClient *database.Client, count int) {
	d := dbClient.Ent.Decision.Query().AllX(context.Background())
	assert.Len(t, d, count)
}

func assertTotalValidDecisionCount(t *testing.T, dbClient *database.Client, count int) {
	d := dbClient.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now()),
	).AllX(context.Background())
	assert.Len(t, d, count)
}

func jsonMarshalX(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func assertTotalAlertCount(t *testing.T, dbClient *database.Client, count int) {
	d := dbClient.Ent.Alert.Query().AllX(context.Background())
	assert.Len(t, d, count)
}

func TestAPICCAPIPullIsOld(t *testing.T) {
	api := getAPIC(t)
	isOld, err := api.CAPIPullIsOld()
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, isOld)

	decision := api.dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetType("IP").
		SetScope("Country").
		SetValue("Blah").
		SetOrigin(SCOPE_CAPI).
		SaveX(context.Background())

	api.dbClient.Ent.Alert.Create().
		SetCreatedAt(time.Now()).
		SetScenario("crowdsec/test").
		AddDecisions(
			decision,
		).
		SaveX(context.Background())

	isOld, err = api.CAPIPullIsOld()
	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, isOld)
}

func TestAPICFetchScenariosListFromDB(t *testing.T) {
	api := getAPIC(t)
	testCases := []struct {
		name                    string
		machineIDsWithScenarios map[string]string
		expectedScenarios       []string
	}{
		{
			name: "Simple one machine with two scenarios",
			machineIDsWithScenarios: map[string]string{
				"a": "crowdsecurity/http-bf,crowdsecurity/ssh-bf",
			},
			expectedScenarios: []string{"crowdsecurity/ssh-bf", "crowdsecurity/http-bf"},
		},
		{
			name: "Multi machine with custom+hub scenarios",
			machineIDsWithScenarios: map[string]string{
				"a": "crowdsecurity/http-bf,crowdsecurity/ssh-bf,my_scenario",
				"b": "crowdsecurity/http-bf,crowdsecurity/ssh-bf,foo_scenario",
			},
			expectedScenarios: []string{"crowdsecurity/ssh-bf", "crowdsecurity/http-bf", "my_scenario", "foo_scenario"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for machineID, scenarios := range tc.machineIDsWithScenarios {
				api.dbClient.Ent.Machine.Create().
					SetMachineId(machineID).
					SetPassword(testPassword.String()).
					SetIpAddress("1.2.3.4").
					SetScenarios(scenarios).
					ExecX(context.Background())
			}
			scenarios, err := api.FetchScenariosListFromDB()
			for machineID := range tc.machineIDsWithScenarios {
				api.dbClient.Ent.Machine.Delete().Where(machine.MachineIdEQ(machineID)).ExecX(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			} else {
				sort.Strings(scenarios)
				sort.Strings(tc.expectedScenarios)
				assert.Equal(t, scenarios, tc.expectedScenarios)
			}
		})

	}
}

func TestNewAPIC(t *testing.T) {
	var testConfig *csconfig.OnlineApiClientCfg
	setConfig := func() {
		testConfig = &csconfig.OnlineApiClientCfg{
			Credentials: &csconfig.ApiCredentialsCfg{
				URL:      "foobar",
				Login:    "foo",
				Password: "bar",
			},
		}
	}
	type args struct {
		dbClient      *database.Client
		consoleConfig *csconfig.ConsoleConfig
	}
	tests := []struct {
		name          string
		args          args
		wantErr       bool
		errorContains string
		action        func()
	}{
		{
			name:   "simple",
			action: func() {},
			args: args{
				dbClient:      getDBClient(t),
				consoleConfig: LoadTestConfig().API.Server.ConsoleConfig,
			},
		},
		{
			name:   "error in parsing URL",
			action: func() { testConfig.Credentials.URL = "foobar http://" },
			args: args{
				dbClient:      getDBClient(t),
				consoleConfig: LoadTestConfig().API.Server.ConsoleConfig,
			},
			wantErr:       true,
			errorContains: "first path segment in URL cannot contain colon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setConfig()
			tt.action()
			_, err := NewAPIC(testConfig, tt.args.dbClient, tt.args.consoleConfig)
			if tt.wantErr {
				assert.ErrorContains(t, err, tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPICHandleDeletedDecisions(t *testing.T) {
	api := getAPIC(t)
	_, deleteCounters := makeAddAndDeleteCounters()

	decision1 := api.dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetType("ban").
		SetScope("IP").
		SetValue("1.2.3.4").
		SetOrigin(SCOPE_CAPI).
		SaveX(context.Background())

	api.dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetType("ban").
		SetScope("IP").
		SetValue("1.2.3.4").
		SetOrigin(SCOPE_CAPI).
		SaveX(context.Background())

	assertTotalDecisionCount(t, api.dbClient, 2)

	nbDeleted, err := api.HandleDeletedDecisions([]*models.Decision{{
		Value:    types.StrPtr("1.2.3.4"),
		Origin:   &SCOPE_CAPI,
		Type:     &decision1.Type,
		Scenario: types.StrPtr("crowdsec/test"),
		Scope:    types.StrPtr("IP"),
	}}, deleteCounters)

	assert.NoError(t, err)
	assert.Equal(t, nbDeleted, 2)
	assert.Equal(t, deleteCounters[SCOPE_CAPI]["all"], 2)
}

func TestAPICGetMetrics(t *testing.T) {
	api := getAPIC(t)
	cleanUp := func() {
		api.dbClient.Ent.Bouncer.Delete().ExecX(context.Background())
		api.dbClient.Ent.Machine.Delete().ExecX(context.Background())
	}
	testCases := []struct {
		name           string
		machineIDs     []string
		bouncers       []string
		expectedMetric *models.Metrics
	}{
		{
			name:       "simple",
			machineIDs: []string{"a", "b", "c"},
			bouncers:   []string{"1", "2", "3"},
			expectedMetric: &models.Metrics{
				ApilVersion: types.StrPtr(cwversion.VersionStr()),
				Bouncers: []*models.MetricsBouncerInfo{
					{
						CustomName: "1",
						LastPull:   time.Time{}.String(),
					}, {
						CustomName: "2",
						LastPull:   time.Time{}.String(),
					}, {
						CustomName: "3",
						LastPull:   time.Time{}.String(),
					},
				},
				Machines: []*models.MetricsAgentInfo{
					{
						Name:       "a",
						LastPush:   time.Time{}.String(),
						LastUpdate: time.Time{}.String(),
					},
					{
						Name:       "b",
						LastPush:   time.Time{}.String(),
						LastUpdate: time.Time{}.String(),
					},
					{
						Name:       "c",
						LastPush:   time.Time{}.String(),
						LastUpdate: time.Time{}.String(),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cleanUp()
			for i, machineID := range testCase.machineIDs {
				api.dbClient.Ent.Machine.Create().
					SetMachineId(machineID).
					SetPassword(testPassword.String()).
					SetIpAddress(fmt.Sprintf("1.2.3.%d", i)).
					SetScenarios("crowdsecurity/test").
					SetLastPush(time.Time{}).
					SetUpdatedAt(time.Time{}).
					ExecX(context.Background())
			}

			for i, bouncerName := range testCase.bouncers {
				api.dbClient.Ent.Bouncer.Create().
					SetIPAddress(fmt.Sprintf("1.2.3.%d", i)).
					SetName(bouncerName).
					SetAPIKey("foobar").
					SetRevoked(false).
					SetLastPull(time.Time{}).
					ExecX(context.Background())
			}

			if foundMetrics, err := api.GetMetrics(); err != nil {
				t.Fatal(err)
			} else {
				assert.Equal(t, foundMetrics.Bouncers, testCase.expectedMetric.Bouncers)
				assert.Equal(t, foundMetrics.Machines, testCase.expectedMetric.Machines)

			}
		})
	}
}

func TestCreateAlertsForDecision(t *testing.T) {

	httpBfDecisionList := &models.Decision{
		Origin:   &SCOPE_LISTS,
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
	}

	sshBfDecisionList := &models.Decision{
		Origin:   &SCOPE_LISTS,
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
	}

	httpBfDecisionCommunity := &models.Decision{
		Origin:   &SCOPE_CAPI,
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
	}

	sshBfDecisionCommunity := &models.Decision{
		Origin:   &SCOPE_CAPI,
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
	}
	type args struct {
		decisions []*models.Decision
	}
	tests := []struct {
		name string
		args args
		want []*models.Alert
	}{
		{
			name: "2 decisions CAPI List Decisions should create 2 alerts",
			args: args{
				decisions: []*models.Decision{
					httpBfDecisionList,
					sshBfDecisionList,
				},
			},
			want: []*models.Alert{
				createAlertForDecision(httpBfDecisionList),
				createAlertForDecision(sshBfDecisionList),
			},
		},
		{
			name: "2 decisions CAPI List same scenario decisions should create 1 alert",
			args: args{
				decisions: []*models.Decision{
					httpBfDecisionList,
					httpBfDecisionList,
				},
			},
			want: []*models.Alert{
				createAlertForDecision(httpBfDecisionList),
			},
		},
		{
			name: "5 decisions from community list should create 1 alert",
			args: args{
				decisions: []*models.Decision{
					httpBfDecisionCommunity,
					httpBfDecisionCommunity,
					sshBfDecisionCommunity,
					sshBfDecisionCommunity,
					sshBfDecisionCommunity,
				},
			},
			want: []*models.Alert{
				createAlertForDecision(sshBfDecisionCommunity),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createAlertsForDecisions(tt.args.decisions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createAlertsForDecisions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFillAlertsWithDecisions(t *testing.T) {
	httpBfDecisionCommunity := &models.Decision{
		Origin:   &SCOPE_CAPI,
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
		Scope:    types.StrPtr("ip"),
	}

	sshBfDecisionCommunity := &models.Decision{
		Origin:   &SCOPE_CAPI,
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
		Scope:    types.StrPtr("ip"),
	}

	httpBfDecisionList := &models.Decision{
		Origin:   &SCOPE_LISTS,
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
		Scope:    types.StrPtr("ip"),
	}

	sshBfDecisionList := &models.Decision{
		Origin:   &SCOPE_LISTS,
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
		Scope:    types.StrPtr("ip"),
	}
	type args struct {
		alerts    []*models.Alert
		decisions []*models.Decision
	}
	tests := []struct {
		name string
		args args
		want []*models.Alert
	}{
		{
			name: "1 CAPI alert should pair up with n CAPI decisions",
			args: args{
				alerts:    []*models.Alert{createAlertForDecision(httpBfDecisionCommunity)},
				decisions: []*models.Decision{httpBfDecisionCommunity, sshBfDecisionCommunity, sshBfDecisionCommunity, httpBfDecisionCommunity},
			},
			want: []*models.Alert{
				func() *models.Alert {
					a := createAlertForDecision(httpBfDecisionCommunity)
					a.Decisions = []*models.Decision{httpBfDecisionCommunity, sshBfDecisionCommunity, sshBfDecisionCommunity, httpBfDecisionCommunity}
					return a
				}(),
			},
		},
		{
			name: "List alert should pair up only with decisions having same scenario",
			args: args{
				alerts:    []*models.Alert{createAlertForDecision(httpBfDecisionList), createAlertForDecision(sshBfDecisionList)},
				decisions: []*models.Decision{httpBfDecisionList, httpBfDecisionList, sshBfDecisionList, sshBfDecisionList},
			},
			want: []*models.Alert{
				func() *models.Alert {
					a := createAlertForDecision(httpBfDecisionList)
					a.Decisions = []*models.Decision{httpBfDecisionList, httpBfDecisionList}
					return a
				}(),
				func() *models.Alert {
					a := createAlertForDecision(sshBfDecisionList)
					a.Decisions = []*models.Decision{sshBfDecisionList, sshBfDecisionList}
					return a
				}(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			add_counters, _ := makeAddAndDeleteCounters()
			if got := fillAlertsWithDecisions(tt.args.alerts, tt.args.decisions, add_counters); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fillAlertsWithDecisions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPICPullTop(t *testing.T) {
	api := getAPIC(t)
	api.dbClient.Ent.Decision.Create().
		SetOrigin(SCOPE_LISTS).
		SetType("ban").
		SetValue("9.9.9.9").
		SetScope("Ip").
		SetScenario("crowdsecurity/ssh-bf").
		SetUntil(time.Now().Add(time.Hour)).
		ExecX(context.Background())
	assertTotalDecisionCount(t, api.dbClient, 1)
	assertTotalValidDecisionCount(t, api.dbClient, 1)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/api/decisions/stream", httpmock.NewBytesResponder(
		200, jsonMarshalX(
			models.DecisionsStreamResponse{
				Deleted: models.GetDecisionsResponse{
					&models.Decision{
						Origin:   &SCOPE_LISTS,
						Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
						Value:    types.StrPtr("9.9.9.9"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					}, // Thie is already present in DB
					&models.Decision{
						Origin:   &SCOPE_LISTS,
						Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
						Value:    types.StrPtr("9.1.9.9"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					}, // This not present in DB.
				},
				New: models.GetDecisionsResponse{
					&models.Decision{
						Origin:   &SCOPE_CAPI,
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Value:    types.StrPtr("1.2.3.4"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					},
					&models.Decision{
						Origin:   &SCOPE_CAPI,
						Scenario: types.StrPtr("crowdsecurity/test2"),
						Value:    types.StrPtr("1.2.3.5"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					}, // These two are from community list.
					&models.Decision{
						Origin:   &SCOPE_LISTS,
						Scenario: types.StrPtr("crowdsecurity/http-bf"),
						Value:    types.StrPtr("1.2.3.6"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					},
					&models.Decision{
						Origin:   &SCOPE_LISTS,
						Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
						Value:    types.StrPtr("1.2.3.7"),
						Scope:    types.StrPtr("Ip"),
						Duration: types.StrPtr("24h"),
						Type:     types.StrPtr("ban"),
					}, // These two are from list subscription.
				},
			},
		),
	))
	url, err := url.ParseRequestURI("http://api.crowdsec.net/")
	if err != nil {
		t.Fatal(err)
	}
	apic, err := apiclient.NewDefaultClient(
		url,
		"/api",
		fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	api.apiClient = apic
	err = api.PullTop()
	if err != nil {
		t.Fatal(err)
	}

	assertTotalDecisionCount(t, api.dbClient, 5)
	assertTotalValidDecisionCount(t, api.dbClient, 4)
	assertTotalAlertCount(t, api.dbClient, 3) // 2 for list sub , 1 for community list.
	alerts := api.dbClient.Ent.Alert.Query().AllX(context.Background())
	validDecisions := api.dbClient.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now())).
		AllX(context.Background())

	decisionScenarioFreq := make(map[string]int)
	alertScenario := make(map[string]int)

	for _, alert := range alerts {
		alertScenario[alert.SourceScope]++
	}
	assert.Equal(t, len(alertScenario), 3)
	assert.Equal(t, alertScenario[SCOPE_CAPI_ALIAS], 1)
	assert.Equal(t, alertScenario["lists:crowdsecurity/ssh-bf"], 1)
	assert.Equal(t, alertScenario["lists:crowdsecurity/http-bf"], 1)

	for _, decisions := range validDecisions {
		decisionScenarioFreq[decisions.Scenario]++
	}

	assert.Equal(t, decisionScenarioFreq["crowdsecurity/http-bf"], 1)
	assert.Equal(t, decisionScenarioFreq["crowdsecurity/ssh-bf"], 1)
	assert.Equal(t, decisionScenarioFreq["crowdsecurity/test1"], 1)
	assert.Equal(t, decisionScenarioFreq["crowdsecurity/test2"], 1)
}

func TestAPICPush(t *testing.T) {

	testCases := []struct {
		name          string
		alerts        []*models.Alert
		expectedCalls int
	}{
		{
			name: "simple single alert",
			alerts: []*models.Alert{
				{
					Scenario:        types.StrPtr("crowdsec/test"),
					ScenarioHash:    types.StrPtr("certified"),
					ScenarioVersion: types.StrPtr("v1.0"),
					Simulated:       types.BoolPtr(false),
				},
			},
			expectedCalls: 1,
		},
		{
			name: "simulated alert is not pushed",
			alerts: []*models.Alert{
				{
					Scenario:        types.StrPtr("crowdsec/test"),
					ScenarioHash:    types.StrPtr("certified"),
					ScenarioVersion: types.StrPtr("v1.0"),
					Simulated:       types.BoolPtr(true),
				},
			},
			expectedCalls: 0,
		},
		{
			name:          "1 request per 50 alerts",
			expectedCalls: 2,
			alerts: func() []*models.Alert {
				alerts := make([]*models.Alert, 100)
				for i := 0; i < 100; i++ {
					alerts[i] = &models.Alert{
						Scenario:        types.StrPtr("crowdsec/test"),
						ScenarioHash:    types.StrPtr("certified"),
						ScenarioVersion: types.StrPtr("v1.0"),
						Simulated:       types.BoolPtr(false),
					}
				}
				return alerts
			}(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			api := getAPIC(t)
			api.pushInterval = time.Millisecond
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			if err != nil {
				t.Fatal(err)
			}
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			apic, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			api.apiClient = apic
			httpmock.RegisterResponder("POST", "http://api.crowdsec.net/api/signals", httpmock.NewBytesResponder(200, []byte{}))
			go func() {
				api.alertToPush <- testCase.alerts
				time.Sleep(time.Second)
				api.Shutdown()
			}()
			if err := api.Push(); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, httpmock.GetTotalCallCount(), testCase.expectedCalls)
		})
	}
}

func TestAPICSendMetrics(t *testing.T) {
	api := getAPIC(t)
	testCases := []struct {
		name            string
		duration        time.Duration
		expectedCalls   int
		setUp           func()
		metricsInterval time.Duration
	}{
		{
			name:            "basic",
			duration:        time.Millisecond * 5,
			metricsInterval: time.Millisecond,
			expectedCalls:   5,
			setUp:           func() {},
		},
		{
			name:            "with some metrics",
			duration:        time.Millisecond * 5,
			metricsInterval: time.Millisecond,
			expectedCalls:   5,
			setUp: func() {
				api.dbClient.Ent.Machine.Create().
					SetMachineId("1234").
					SetPassword(testPassword.String()).
					SetIpAddress("1.2.3.4").
					SetScenarios("crowdsecurity/test").
					SetLastPush(time.Time{}).
					SetUpdatedAt(time.Time{}).
					ExecX(context.Background())

				api.dbClient.Ent.Bouncer.Create().
					SetIPAddress("1.2.3.6").
					SetName("someBouncer").
					SetAPIKey("foobar").
					SetRevoked(false).
					SetLastPull(time.Time{}).
					ExecX(context.Background())
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			api = getAPIC(t)
			api.pushInterval = time.Millisecond
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			if err != nil {
				t.Fatal(err)
			}
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			apic, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			api.apiClient = apic
			api.metricsInterval = testCase.metricsInterval
			httpmock.RegisterNoResponder(httpmock.NewBytesResponder(200, []byte{}))
			testCase.setUp()

			go func() {
				if err := api.SendMetrics(); err != nil {
					panic(err)
				}
			}()
			if runtime.GOOS == "windows" {
				time.Sleep(time.Second)
			} else {
				time.Sleep(testCase.duration)
			}
			assert.LessOrEqual(t, absDiff(testCase.expectedCalls, httpmock.GetTotalCallCount()), 2)
		})
	}
}

func TestAPICPull(t *testing.T) {
	api := getAPIC(t)
	testCases := []struct {
		name                  string
		setUp                 func()
		expectedDecisionCount int
		logContains           string
	}{
		{
			name:        "test pull if no scenarios are present",
			setUp:       func() {},
			logContains: "scenario list is empty, will not pull yet",
		},
		{
			name: "test pull",
			setUp: func() {
				api.dbClient.Ent.Machine.Create().
					SetMachineId("1.2.3.4").
					SetPassword(testPassword.String()).
					SetIpAddress("1.2.3.4").
					SetScenarios("crowdsecurity/ssh-bf").
					ExecX(context.Background())
			},
			expectedDecisionCount: 1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			api = getAPIC(t)
			api.pullInterval = time.Millisecond
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			if err != nil {
				t.Fatal(err)
			}
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			apic, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			api.apiClient = apic
			httpmock.RegisterNoResponder(httpmock.NewBytesResponder(200, jsonMarshalX(
				models.DecisionsStreamResponse{
					New: models.GetDecisionsResponse{
						&models.Decision{
							Origin:   &SCOPE_CAPI,
							Scenario: types.StrPtr("crowdsecurity/test2"),
							Value:    types.StrPtr("1.2.3.5"),
							Scope:    types.StrPtr("Ip"),
							Duration: types.StrPtr("24h"),
							Type:     types.StrPtr("ban"),
						},
					},
				},
			)))
			testCase.setUp()
			var buf bytes.Buffer
			go func() {
				logrus.SetOutput(&buf)
				if err := api.Pull(); err != nil {
					panic(err)
				}
			}()
			//Slightly long because the CI runner for windows are slow, and this can lead to random failure
			time.Sleep(time.Millisecond * 500)
			logrus.SetOutput(os.Stderr)
			assert.Contains(t, buf.String(), testCase.logContains)
			assertTotalDecisionCount(t, api.dbClient, testCase.expectedDecisionCount)
		})
	}
}

func TestShouldShareAlert(t *testing.T) {

	testCases := []struct {
		name          string
		consoleConfig *csconfig.ConsoleConfig
		alert         *models.Alert
		expectedRet   bool
		expectedTrust string
	}{
		{
			name: "custom alert should be shared if config enables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareCustomScenarios: types.BoolPtr(true),
			},
			alert:         &models.Alert{Simulated: types.BoolPtr(false)},
			expectedRet:   true,
			expectedTrust: "custom",
		},
		{
			name: "custom alert should not be shared if config disables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareCustomScenarios: types.BoolPtr(false),
			},
			alert:         &models.Alert{Simulated: types.BoolPtr(false)},
			expectedRet:   false,
			expectedTrust: "custom",
		},
		{
			name: "manual alert should be shared if config enables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareManualDecisions: types.BoolPtr(true),
			},
			alert: &models.Alert{
				Simulated: types.BoolPtr(false),
				Decisions: []*models.Decision{{Origin: types.StrPtr("cscli")}},
			},
			expectedRet:   true,
			expectedTrust: "manual",
		},
		{
			name: "manaul alert should not be shared if config disables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareManualDecisions: types.BoolPtr(false),
			},
			alert: &models.Alert{
				Simulated: types.BoolPtr(false),
				Decisions: []*models.Decision{{Origin: types.StrPtr("cscli")}},
			},
			expectedRet:   false,
			expectedTrust: "manual",
		},
		{
			name: "manual alert should be shared if config enables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareTaintedScenarios: types.BoolPtr(true),
			},
			alert: &models.Alert{
				Simulated:    types.BoolPtr(false),
				ScenarioHash: types.StrPtr("whateverHash"),
			},
			expectedRet:   true,
			expectedTrust: "tainted",
		},
		{
			name: "manaul alert should not be shared if config disables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareTaintedScenarios: types.BoolPtr(false),
			},
			alert: &models.Alert{
				Simulated:    types.BoolPtr(false),
				ScenarioHash: types.StrPtr("whateverHash"),
			},
			expectedRet:   false,
			expectedTrust: "tainted",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ret := shouldShareAlert(testCase.alert, testCase.consoleConfig)
			assert.Equal(t, ret, testCase.expectedRet)
		})
	}
}
