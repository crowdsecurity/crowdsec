package apiserver

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
)

func TestCAPIPullIsOld(t *testing.T) {
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

func getDBClient(t *testing.T) *database.Client {
	t.Helper()
	dbPath, err := os.CreateTemp("/tmp/", "*sqlite")
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
	}

}

func Test_apic_FetchScenariosListFromDB(t *testing.T) {
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

func Test_apic_HandleDeletedDecisions(t *testing.T) {
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

func assertTotalDecisionCount(t *testing.T, dbClient *database.Client, count int) {
	d := dbClient.Ent.Decision.Query().AllX(context.Background())
	assert.Len(t, d, count)
}

func Test_createAlertsForDecision(t *testing.T) {

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
