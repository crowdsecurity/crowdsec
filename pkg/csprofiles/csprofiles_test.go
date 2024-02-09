package csprofiles

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var (
	scope     = "Country"
	typ       = "ban"
	boolFalse = false
	boolTrue  = true
	duration  = "1h"

	value    = "CH"
	scenario = "ssh-bf"
)

func TestNewProfile(t *testing.T) {
	tests := []struct {
		name              string
		profileCfg        *csconfig.ProfileCfg
		expectedNbProfile int
	}{
		{
			name: "filter ok and duration_expr ok",
			profileCfg: &csconfig.ProfileCfg{
				Filters: []string{
					"1==1",
				},
				DurationExpr: "1==1",
				Debug:        &boolFalse,
				Decisions: []models.Decision{
					{Type: &typ, Scope: &scope, Simulated: &boolTrue, Duration: &duration},
				},
			},
			expectedNbProfile: 1,
		},
		{
			name: "filter NOK and duration_expr ok",
			profileCfg: &csconfig.ProfileCfg{
				Filters: []string{
					"1==1",
					"unknownExprHelper() == 'foo'",
				},
				DurationExpr: "1==1",
				Debug:        &boolFalse,
				Decisions: []models.Decision{
					{Type: &typ, Scope: &scope, Simulated: &boolFalse, Duration: &duration},
				},
			},
			expectedNbProfile: 0,
		},
		{
			name: "filter ok and duration_expr NOK",
			profileCfg: &csconfig.ProfileCfg{
				Filters: []string{
					"1==1",
				},
				DurationExpr: "unknownExprHelper() == 'foo'",
				Debug:        &boolFalse,
				Decisions: []models.Decision{
					{Type: &typ, Scope: &scope, Simulated: &boolFalse, Duration: &duration},
				},
			},
			expectedNbProfile: 0,
		},
		{
			name: "filter ok and duration_expr ok + DEBUG",
			profileCfg: &csconfig.ProfileCfg{
				Filters: []string{
					"1==1",
				},
				DurationExpr: "1==1",
				Debug:        &boolTrue,
				Decisions: []models.Decision{
					{Type: &typ, Scope: &scope, Simulated: &boolFalse, Duration: &duration},
				},
			},
			expectedNbProfile: 1,
		},
		{
			name: "filter ok and no duration",
			profileCfg: &csconfig.ProfileCfg{
				Filters: []string{
					"1==1",
				},
				Debug: &boolTrue,
				Decisions: []models.Decision{
					{Type: &typ, Scope: &scope, Simulated: &boolFalse},
				},
			},
			expectedNbProfile: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			profilesCfg := []*csconfig.ProfileCfg{
				test.profileCfg,
			}
			profile, _ := NewProfile(profilesCfg)
			fmt.Printf("expected : %+v | result : %+v", test.expectedNbProfile, len(profile))
			require.Len(t, profile, test.expectedNbProfile)
		})
	}
}

func TestEvaluateProfile(t *testing.T) {
	type args struct {
		profileCfg *csconfig.ProfileCfg
		Alert      *models.Alert
	}

	exprhelpers.Init(nil)

	tests := []struct {
		name                  string
		args                  args
		expectedDecisionCount int // count of expected decisions
		expectedDuration      string
		expectedMatchStatus   bool
	}{
		{
			name: "simple pass single expr",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{fmt.Sprintf("Alert.GetScenario() == \"%s\"", scenario)},
					Debug:   &boolFalse,
				},
				Alert: &models.Alert{Remediation: true, Scenario: &scenario},
			},
			expectedDecisionCount: 0,
			expectedMatchStatus:   true,
		},
		{
			name: "simple fail single expr",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{"Alert.GetScenario() == \"Foo\""},
				},
				Alert: &models.Alert{Remediation: true},
			},
			expectedDecisionCount: 0,
			expectedMatchStatus:   false,
		},
		{
			name: "1 expr fail 1 expr pass should still eval to match",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{"1==1", "1!=1"},
				},
				Alert: &models.Alert{Remediation: true},
			},
			expectedDecisionCount: 0,
			expectedMatchStatus:   true,
		},
		{
			name: "simple filter with  2 decision",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{"1==1"},
					Decisions: []models.Decision{
						{Type: &typ, Scope: &scope, Simulated: &boolTrue, Duration: &duration},
						{Type: &typ, Scope: &scope, Simulated: &boolFalse, Duration: &duration},
					},
				},
				Alert: &models.Alert{Remediation: true, Scenario: &scenario, Source: &models.Source{Value: &value}},
			},
			expectedDecisionCount: 2,
			expectedMatchStatus:   true,
		},
		{
			name: "simple filter with decision_expr",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{"1==1"},
					Decisions: []models.Decision{
						{Type: &typ, Scope: &scope, Simulated: &boolFalse},
					},
					DurationExpr: "Sprintf('%dh', 4*4)",
				},
				Alert: &models.Alert{Remediation: true, Scenario: &scenario, Source: &models.Source{Value: &value}},
			},
			expectedDecisionCount: 1,
			expectedDuration:      "16h",
			expectedMatchStatus:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			profilesCfg := []*csconfig.ProfileCfg{
				tt.args.profileCfg,
			}
			profile, err := NewProfile(profilesCfg)
			if err != nil {
				t.Errorf("failed to get newProfile : %+v", err)
			}
			got, got1, _ := profile[0].EvaluateProfile(tt.args.Alert)
			if !reflect.DeepEqual(len(got), tt.expectedDecisionCount) {
				t.Errorf("EvaluateProfile() got = %+v, want %+v", got, tt.expectedDecisionCount)
			}
			if got1 != tt.expectedMatchStatus {
				t.Errorf("EvaluateProfile() got1 = %v, want %v", got1, tt.expectedMatchStatus)
			}
			if tt.expectedDuration != "" {
				require.Equal(t, tt.expectedDuration, *got[0].Duration, "The two durations should be the same")
			}
		})
	}
}
