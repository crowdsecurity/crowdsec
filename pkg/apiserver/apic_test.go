package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func getDBClient(t *testing.T) *database.Client {
	t.Helper()
	dbPath, err := os.CreateTemp("", "*sqlite")
	require.NoError(t, err)
	dbClient, err := database.NewClient(&csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbName: "crowdsec",
		DbPath: dbPath.Name(),
	})
	require.NoError(t, err)
	return dbClient
}

func getAPIC(t *testing.T) *apic {
	t.Helper()
	dbClient := getDBClient(t)
	return &apic{
		AlertsAddChan: make(chan []*models.Alert),
		//DecisionDeleteChan: make(chan []*models.Decision),
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
			ShareContext:          types.BoolPtr(false),
		},
		isPulling: make(chan bool, 1),
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
	require.NoError(t, err)
	assert.True(t, isOld)

	decision := api.dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetType("IP").
		SetScope("Country").
		SetValue("Blah").
		SetOrigin(types.CAPIOrigin).
		SaveX(context.Background())

	api.dbClient.Ent.Alert.Create().
		SetCreatedAt(time.Now()).
		SetScenario("crowdsec/test").
		AddDecisions(
			decision,
		).
		SaveX(context.Background())

	isOld, err = api.CAPIPullIsOld()
	require.NoError(t, err)

	assert.False(t, isOld)
}

func TestAPICFetchScenariosListFromDB(t *testing.T) {
	tests := []struct {
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

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			api := getAPIC(t)
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
			require.NoError(t, err)

			assert.ElementsMatch(t, tc.expectedScenarios, scenarios)
		})

	}
}

func TestNewAPIC(t *testing.T) {
	var testConfig *csconfig.OnlineApiClientCfg
	setConfig := func() {
		testConfig = &csconfig.OnlineApiClientCfg{
			Credentials: &csconfig.ApiCredentialsCfg{
				URL:      "http://foobar/",
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
		name        string
		args        args
		expectedErr string
		action      func()
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
			expectedErr: "first path segment in URL cannot contain colon",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			setConfig()
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterResponder("POST", "http://foobar/v3/watchers/login", httpmock.NewBytesResponder(
				200, jsonMarshalX(
					models.WatcherAuthResponse{
						Code:   200,
						Expire: "2023-01-12T22:51:43Z",
						Token:  "MyToken",
					},
				),
			))
			tc.action()
			_, err := NewAPIC(testConfig, tc.args.dbClient, tc.args.consoleConfig, nil)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
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
		SetOrigin(types.CAPIOrigin).
		SaveX(context.Background())

	api.dbClient.Ent.Decision.Create().
		SetUntil(time.Now().Add(time.Hour)).
		SetScenario("crowdsec/test").
		SetType("ban").
		SetScope("IP").
		SetValue("1.2.3.4").
		SetOrigin(types.CAPIOrigin).
		SaveX(context.Background())

	assertTotalDecisionCount(t, api.dbClient, 2)

	nbDeleted, err := api.HandleDeletedDecisions([]*models.Decision{{
		Value:    types.StrPtr("1.2.3.4"),
		Origin:   types.StrPtr(types.CAPIOrigin),
		Type:     &decision1.Type,
		Scenario: types.StrPtr("crowdsec/test"),
		Scope:    types.StrPtr("IP"),
	}}, deleteCounters)

	assert.NoError(t, err)
	assert.Equal(t, 2, nbDeleted)
	assert.Equal(t, 2, deleteCounters[types.CAPIOrigin]["all"])
}

func TestAPICGetMetrics(t *testing.T) {
	cleanUp := func(api *apic) {
		api.dbClient.Ent.Bouncer.Delete().ExecX(context.Background())
		api.dbClient.Ent.Machine.Delete().ExecX(context.Background())
	}
	tests := []struct {
		name           string
		machineIDs     []string
		bouncers       []string
		expectedMetric *models.Metrics
	}{
		{
			name:       "no bouncers nor machines should still have bouncers/machines keys in output",
			machineIDs: []string{},
			bouncers:   []string{},
			expectedMetric: &models.Metrics{
				ApilVersion: types.StrPtr(cwversion.VersionStr()),
				Bouncers:    []*models.MetricsBouncerInfo{},
				Machines:    []*models.MetricsAgentInfo{},
			},
		},
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
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			apiClient := getAPIC(t)
			cleanUp(apiClient)
			for i, machineID := range tc.machineIDs {
				apiClient.dbClient.Ent.Machine.Create().
					SetMachineId(machineID).
					SetPassword(testPassword.String()).
					SetIpAddress(fmt.Sprintf("1.2.3.%d", i)).
					SetScenarios("crowdsecurity/test").
					SetLastPush(time.Time{}).
					SetUpdatedAt(time.Time{}).
					ExecX(context.Background())
			}

			for i, bouncerName := range tc.bouncers {
				apiClient.dbClient.Ent.Bouncer.Create().
					SetIPAddress(fmt.Sprintf("1.2.3.%d", i)).
					SetName(bouncerName).
					SetAPIKey("foobar").
					SetRevoked(false).
					SetLastPull(time.Time{}).
					ExecX(context.Background())
			}

			foundMetrics, err := apiClient.GetMetrics()
			require.NoError(t, err)

			assert.Equal(t, tc.expectedMetric.Bouncers, foundMetrics.Bouncers)
			assert.Equal(t, tc.expectedMetric.Machines, foundMetrics.Machines)

		})
	}
}

func TestCreateAlertsForDecision(t *testing.T) {
	httpBfDecisionList := &models.Decision{
		Origin:   types.StrPtr(types.ListOrigin),
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
	}

	sshBfDecisionList := &models.Decision{
		Origin:   types.StrPtr(types.ListOrigin),
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
	}

	httpBfDecisionCommunity := &models.Decision{
		Origin:   types.StrPtr(types.CAPIOrigin),
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
	}

	sshBfDecisionCommunity := &models.Decision{
		Origin:   types.StrPtr(types.CAPIOrigin),
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
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := createAlertsForDecisions(tc.args.decisions); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("createAlertsForDecisions() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFillAlertsWithDecisions(t *testing.T) {
	httpBfDecisionCommunity := &models.Decision{
		Origin:   types.StrPtr(types.CAPIOrigin),
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
		Scope:    types.StrPtr("ip"),
	}

	sshBfDecisionCommunity := &models.Decision{
		Origin:   types.StrPtr(types.CAPIOrigin),
		Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
		Scope:    types.StrPtr("ip"),
	}

	httpBfDecisionList := &models.Decision{
		Origin:   types.StrPtr(types.ListOrigin),
		Scenario: types.StrPtr("crowdsecurity/http-bf"),
		Scope:    types.StrPtr("ip"),
	}

	sshBfDecisionList := &models.Decision{
		Origin:   types.StrPtr(types.ListOrigin),
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
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			addCounters, _ := makeAddAndDeleteCounters()
			if got := fillAlertsWithDecisions(tc.args.alerts, tc.args.decisions, addCounters); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("fillAlertsWithDecisions() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPICWhitelists(t *testing.T) {
	api := getAPIC(t)
	//one whitelist on IP, one on CIDR
	api.whitelists = &csconfig.CapiWhitelist{}
	ipwl1 := "9.2.3.4"
	ip := net.ParseIP(ipwl1)
	api.whitelists.Ips = append(api.whitelists.Ips, ip)
	ipwl1 = "7.2.3.4"
	ip = net.ParseIP(ipwl1)
	api.whitelists.Ips = append(api.whitelists.Ips, ip)
	cidrwl1 := "13.2.3.0/24"
	_, tnet, err := net.ParseCIDR(cidrwl1)
	if err != nil {
		t.Fatalf("unable to parse cidr : %s", err)
	}
	api.whitelists.Cidrs = append(api.whitelists.Cidrs, tnet)
	cidrwl1 = "11.2.3.0/24"
	_, tnet, err = net.ParseCIDR(cidrwl1)
	if err != nil {
		t.Fatalf("unable to parse cidr : %s", err)
	}
	api.whitelists.Cidrs = append(api.whitelists.Cidrs, tnet)
	api.dbClient.Ent.Decision.Create().
		SetOrigin(types.CAPIOrigin).
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
			modelscapi.GetDecisionsStreamResponse{
				Deleted: modelscapi.GetDecisionsStreamResponseDeleted{
					&modelscapi.GetDecisionsStreamResponseDeletedItem{
						Decisions: []string{
							"9.9.9.9", // This is already present in DB
							"9.1.9.9", // This not present in DB
						},
						Scope: types.StrPtr("Ip"),
					}, // This is already present in DB
				},
				New: modelscapi.GetDecisionsStreamResponseNew{
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("13.2.3.4"), //wl by cidr
								Duration: types.StrPtr("24h"),
							},
						},
					},

					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("2.2.3.4"),
								Duration: types.StrPtr("24h"),
							},
						},
					},
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test2"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("13.2.3.5"), //wl by cidr
								Duration: types.StrPtr("24h"),
							},
						},
					}, // These two are from community list.
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("6.2.3.4"),
								Duration: types.StrPtr("24h"),
							},
						},
					},
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("9.2.3.4"), //wl by ip
								Duration: types.StrPtr("24h"),
							},
						},
					},
				},
				Links: &modelscapi.GetDecisionsStreamResponseLinks{
					Blocklists: []*modelscapi.BlocklistLink{
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist1"),
							Name:        types.StrPtr("blocklist1"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist2"),
							Name:        types.StrPtr("blocklist2"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
					},
				},
			},
		),
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist1", httpmock.NewStringResponder(
		200, "1.2.3.6",
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist2", httpmock.NewStringResponder(
		200, "1.2.3.7",
	))
	url, err := url.ParseRequestURI("http://api.crowdsec.net/")
	require.NoError(t, err)

	apic, err := apiclient.NewDefaultClient(
		url,
		"/api",
		fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		nil,
	)
	require.NoError(t, err)

	api.apiClient = apic
	err = api.PullTop(false)
	require.NoError(t, err)

	assertTotalDecisionCount(t, api.dbClient, 5) //2 from FIRE + 2 from bl + 1 existing
	assertTotalValidDecisionCount(t, api.dbClient, 4)
	assertTotalAlertCount(t, api.dbClient, 3) // 2 for list sub , 1 for community list.
	alerts := api.dbClient.Ent.Alert.Query().AllX(context.Background())
	validDecisions := api.dbClient.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now())).
		AllX(context.Background())

	decisionScenarioFreq := make(map[string]int)
	decisionIp := make(map[string]int)

	alertScenario := make(map[string]int)

	for _, alert := range alerts {
		alertScenario[alert.SourceScope]++
	}
	assert.Equal(t, 3, len(alertScenario))
	assert.Equal(t, 1, alertScenario[SCOPE_CAPI_ALIAS_ALIAS])
	assert.Equal(t, 1, alertScenario["lists:blocklist1"])
	assert.Equal(t, 1, alertScenario["lists:blocklist2"])

	for _, decisions := range validDecisions {
		decisionScenarioFreq[decisions.Scenario]++
		decisionIp[decisions.Value]++
	}
	assert.Equal(t, 1, decisionIp["2.2.3.4"], 1)
	assert.Equal(t, 1, decisionIp["6.2.3.4"], 1)
	if _, ok := decisionIp["13.2.3.4"]; ok {
		t.Errorf("13.2.3.4 is whitelisted")
	}
	if _, ok := decisionIp["13.2.3.5"]; ok {
		t.Errorf("13.2.3.5 is whitelisted")
	}
	if _, ok := decisionIp["9.2.3.4"]; ok {
		t.Errorf("9.2.3.4 is whitelisted")
	}
	assert.Equal(t, 1, decisionScenarioFreq["blocklist1"], 1)
	assert.Equal(t, 1, decisionScenarioFreq["blocklist2"], 1)
	assert.Equal(t, 2, decisionScenarioFreq["crowdsecurity/test1"], 2)
}

func TestAPICPullTop(t *testing.T) {
	api := getAPIC(t)
	api.dbClient.Ent.Decision.Create().
		SetOrigin(types.CAPIOrigin).
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
			modelscapi.GetDecisionsStreamResponse{
				Deleted: modelscapi.GetDecisionsStreamResponseDeleted{
					&modelscapi.GetDecisionsStreamResponseDeletedItem{
						Decisions: []string{
							"9.9.9.9", // This is already present in DB
							"9.1.9.9", // This not present in DB
						},
						Scope: types.StrPtr("Ip"),
					}, // This is already present in DB
				},
				New: modelscapi.GetDecisionsStreamResponseNew{
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("1.2.3.4"),
								Duration: types.StrPtr("24h"),
							},
						},
					},
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test2"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("1.2.3.5"),
								Duration: types.StrPtr("24h"),
							},
						},
					}, // These two are from community list.
				},
				Links: &modelscapi.GetDecisionsStreamResponseLinks{
					Blocklists: []*modelscapi.BlocklistLink{
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist1"),
							Name:        types.StrPtr("blocklist1"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist2"),
							Name:        types.StrPtr("blocklist2"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
					},
				},
			},
		),
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist1", httpmock.NewStringResponder(
		200, "1.2.3.6",
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist2", httpmock.NewStringResponder(
		200, "1.2.3.7",
	))
	url, err := url.ParseRequestURI("http://api.crowdsec.net/")
	require.NoError(t, err)

	apic, err := apiclient.NewDefaultClient(
		url,
		"/api",
		fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		nil,
	)
	require.NoError(t, err)

	api.apiClient = apic
	err = api.PullTop(false)
	require.NoError(t, err)

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
	assert.Equal(t, 3, len(alertScenario))
	assert.Equal(t, 1, alertScenario[SCOPE_CAPI_ALIAS_ALIAS])
	assert.Equal(t, 1, alertScenario["lists:blocklist1"])
	assert.Equal(t, 1, alertScenario["lists:blocklist2"])

	for _, decisions := range validDecisions {
		decisionScenarioFreq[decisions.Scenario]++
	}

	assert.Equal(t, 1, decisionScenarioFreq["blocklist1"], 1)
	assert.Equal(t, 1, decisionScenarioFreq["blocklist2"], 1)
	assert.Equal(t, 1, decisionScenarioFreq["crowdsecurity/test1"], 1)
	assert.Equal(t, 1, decisionScenarioFreq["crowdsecurity/test2"], 1)
}

func TestAPICPullTopBLCacheFirstCall(t *testing.T) {
	// no decision in db, no last modified parameter.
	api := getAPIC(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/api/decisions/stream", httpmock.NewBytesResponder(
		200, jsonMarshalX(
			modelscapi.GetDecisionsStreamResponse{
				New: modelscapi.GetDecisionsStreamResponseNew{
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("1.2.3.4"),
								Duration: types.StrPtr("24h"),
							},
						},
					},
				},
				Links: &modelscapi.GetDecisionsStreamResponseLinks{
					Blocklists: []*modelscapi.BlocklistLink{
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist1"),
							Name:        types.StrPtr("blocklist1"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
					},
				},
			},
		),
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist1", func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "", req.Header.Get("If-Modified-Since"))
		return httpmock.NewStringResponse(200, "1.2.3.4"), nil
	})
	url, err := url.ParseRequestURI("http://api.crowdsec.net/")
	require.NoError(t, err)

	apic, err := apiclient.NewDefaultClient(
		url,
		"/api",
		fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		nil,
	)
	require.NoError(t, err)

	api.apiClient = apic
	err = api.PullTop(false)
	require.NoError(t, err)

	blocklistConfigItemName := fmt.Sprintf("blocklist:%s:last_pull", *types.StrPtr("blocklist1"))
	lastPullTimestamp, err := api.dbClient.GetConfigItem(blocklistConfigItemName)
	require.NoError(t, err)
	assert.NotEqual(t, "", *lastPullTimestamp)

	// new call should return 304 and should not change lastPullTimestamp
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist1", func(req *http.Request) (*http.Response, error) {
		assert.NotEqual(t, "", req.Header.Get("If-Modified-Since"))
		return httpmock.NewStringResponse(304, ""), nil
	})
	err = api.PullTop(false)
	require.NoError(t, err)
	secondLastPullTimestamp, err := api.dbClient.GetConfigItem(blocklistConfigItemName)
	require.NoError(t, err)
	assert.Equal(t, *lastPullTimestamp, *secondLastPullTimestamp)
}

func TestAPICPullTopBLCacheForceCall(t *testing.T) {
	api := getAPIC(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	// create a decision about to expire. It should force fetch
	alertInstance := api.dbClient.Ent.Alert.
		Create().
		SetScenario("update list").
		SetSourceScope("list:blocklist1").
		SetSourceValue("list:blocklist1").
		SaveX(context.Background())

	api.dbClient.Ent.Decision.Create().
		SetOrigin(types.ListOrigin).
		SetType("ban").
		SetValue("9.9.9.9").
		SetScope("Ip").
		SetScenario("blocklist1").
		SetUntil(time.Now().Add(time.Hour)).
		SetOwnerID(alertInstance.ID).
		ExecX(context.Background())

	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/api/decisions/stream", httpmock.NewBytesResponder(
		200, jsonMarshalX(
			modelscapi.GetDecisionsStreamResponse{
				New: modelscapi.GetDecisionsStreamResponseNew{
					&modelscapi.GetDecisionsStreamResponseNewItem{
						Scenario: types.StrPtr("crowdsecurity/test1"),
						Scope:    types.StrPtr("Ip"),
						Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
							{
								Value:    types.StrPtr("1.2.3.4"),
								Duration: types.StrPtr("24h"),
							},
						},
					},
				},
				Links: &modelscapi.GetDecisionsStreamResponseLinks{
					Blocklists: []*modelscapi.BlocklistLink{
						{
							URL:         types.StrPtr("http://api.crowdsec.net/blocklist1"),
							Name:        types.StrPtr("blocklist1"),
							Scope:       types.StrPtr("Ip"),
							Remediation: types.StrPtr("ban"),
							Duration:    types.StrPtr("24h"),
						},
					},
				},
			},
		),
	))
	httpmock.RegisterResponder("GET", "http://api.crowdsec.net/blocklist1", func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "", req.Header.Get("If-Modified-Since"))
		return httpmock.NewStringResponse(304, ""), nil
	})
	url, err := url.ParseRequestURI("http://api.crowdsec.net/")
	require.NoError(t, err)

	apic, err := apiclient.NewDefaultClient(
		url,
		"/api",
		fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		nil,
	)
	require.NoError(t, err)

	api.apiClient = apic
	err = api.PullTop(false)
	require.NoError(t, err)
}

func TestAPICPush(t *testing.T) {
	tests := []struct {
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
					Source:          &models.Source{},
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
					Source:          &models.Source{},
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
						Source:          &models.Source{},
					}
				}
				return alerts
			}(),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			api := getAPIC(t)
			api.pushInterval = time.Millisecond
			api.pushIntervalFirst = time.Millisecond
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)

			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			apic, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			require.NoError(t, err)

			api.apiClient = apic
			httpmock.RegisterResponder("POST", "http://api.crowdsec.net/api/signals", httpmock.NewBytesResponder(200, []byte{}))
			go func() {
				api.AlertsAddChan <- tc.alerts
				time.Sleep(time.Second)
				api.Shutdown()
			}()
			err = api.Push()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCalls, httpmock.GetTotalCallCount())
		})
	}
}

func TestAPICSendMetrics(t *testing.T) {
	tests := []struct {
		name            string
		duration        time.Duration
		expectedCalls   int
		setUp           func(*apic)
		metricsInterval time.Duration
	}{
		{
			name:            "basic",
			duration:        time.Millisecond * 30,
			metricsInterval: time.Millisecond * 5,
			expectedCalls:   5,
			setUp:           func(api *apic) {},
		},
		{
			name:            "with some metrics",
			duration:        time.Millisecond * 30,
			metricsInterval: time.Millisecond * 5,
			expectedCalls:   5,
			setUp: func(api *apic) {
				api.dbClient.Ent.Machine.Delete().ExecX(context.Background())
				api.dbClient.Ent.Machine.Create().
					SetMachineId("1234").
					SetPassword(testPassword.String()).
					SetIpAddress("1.2.3.4").
					SetScenarios("crowdsecurity/test").
					SetLastPush(time.Time{}).
					SetUpdatedAt(time.Time{}).
					ExecX(context.Background())

				api.dbClient.Ent.Bouncer.Delete().ExecX(context.Background())
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

	httpmock.RegisterResponder("POST", "http://api.crowdsec.net/api/metrics/", httpmock.NewBytesResponder(200, []byte{}))
	httpmock.Activate()
	defer httpmock.Deactivate()

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)

			apiClient, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			require.NoError(t, err)

			api := getAPIC(t)
			api.pushInterval = time.Millisecond
			api.pushIntervalFirst = time.Millisecond
			api.apiClient = apiClient
			api.metricsInterval = tc.metricsInterval
			api.metricsIntervalFirst = tc.metricsInterval
			tc.setUp(api)

			stop := make(chan bool)
			httpmock.ZeroCallCounters()
			go api.SendMetrics(stop)
			time.Sleep(tc.duration)
			stop <- true

			info := httpmock.GetCallCountInfo()
			noResponderCalls := info["NO_RESPONDER"]
			responderCalls := info["POST http://api.crowdsec.net/api/metrics/"]
			assert.LessOrEqual(t, absDiff(tc.expectedCalls, responderCalls), 2)
			assert.Zero(t, noResponderCalls)
		})
	}
}

func TestAPICPull(t *testing.T) {
	api := getAPIC(t)
	tests := []struct {
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

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			api = getAPIC(t)
			api.pullInterval = time.Millisecond
			api.pullIntervalFirst = time.Millisecond
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			apic, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				nil,
			)
			require.NoError(t, err)
			api.apiClient = apic
			httpmock.RegisterNoResponder(httpmock.NewBytesResponder(200, jsonMarshalX(
				modelscapi.GetDecisionsStreamResponse{
					New: modelscapi.GetDecisionsStreamResponseNew{
						&modelscapi.GetDecisionsStreamResponseNewItem{
							Scenario: types.StrPtr("crowdsecurity/ssh-bf"),
							Scope:    types.StrPtr("Ip"),
							Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
								{
									Value:    types.StrPtr("1.2.3.5"),
									Duration: types.StrPtr("24h"),
								},
							},
						},
					},
				},
			)))
			tc.setUp()
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
			assert.Contains(t, buf.String(), tc.logContains)
			assertTotalDecisionCount(t, api.dbClient, tc.expectedDecisionCount)
		})
	}
}

func TestShouldShareAlert(t *testing.T) {
	tests := []struct {
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
				Decisions: []*models.Decision{{Origin: types.StrPtr(types.CscliOrigin)}},
			},
			expectedRet:   true,
			expectedTrust: "manual",
		},
		{
			name: "manual alert should not be shared if config disables it",
			consoleConfig: &csconfig.ConsoleConfig{
				ShareManualDecisions: types.BoolPtr(false),
			},
			alert: &models.Alert{
				Simulated: types.BoolPtr(false),
				Decisions: []*models.Decision{{Origin: types.StrPtr(types.CscliOrigin)}},
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
			name: "manual alert should not be shared if config disables it",
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

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ret := shouldShareAlert(tc.alert, tc.consoleConfig)
			assert.Equal(t, tc.expectedRet, ret)
		})
	}
}
