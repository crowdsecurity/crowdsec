package csprofiles

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var (
	scope     = "Country"
	typ       = "ban"
	simulated = false
	duration  = "1h"

	value    = "CH"
	scenario = "ssh-bf"
)

func TestEvaluateProfile(t *testing.T) {
	type args struct {
		profileCfg *csconfig.ProfileCfg
		profile    *Runtime
		Alert      *models.Alert
	}
	tests := []struct {
		name                  string
		args                  args
		expectedDecisionCount int // count of expected decisions
		expectedMatchStatus   bool
	}{
		{
			name: "simple pass single expr",
			args: args{
				profileCfg: &csconfig.ProfileCfg{
					Filters: []string{fmt.Sprintf("Alert.GetScenario() == \"%s\"", scenario)},
				},
				profile: &Runtime{
					RuntimeFilters:      []*vm.Program{},
					RuntimeDurationExpr: &vm.Program{},
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
				profile: &Runtime{
					RuntimeFilters:      []*vm.Program{},
					RuntimeDurationExpr: &vm.Program{},
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
				profile: &Runtime{
					RuntimeFilters:      []*vm.Program{},
					RuntimeDurationExpr: &vm.Program{},
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
						{Type: &typ, Scope: &scope, Simulated: &simulated, Duration: &duration},
						{Type: &typ, Scope: &scope, Simulated: &simulated, Duration: &duration},
					},
				},
				profile: &Runtime{
					RuntimeFilters:      []*vm.Program{},
					RuntimeDurationExpr: &vm.Program{},
				},
				Alert: &models.Alert{Remediation: true, Scenario: &scenario, Source: &models.Source{Value: &value}},
			},
			expectedDecisionCount: 2,
			expectedMatchStatus:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, filter := range tt.args.profileCfg.Filters {
				runtimeFilter, _ := expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}})))
				tt.args.profile.RuntimeFilters = append(tt.args.profile.RuntimeFilters, runtimeFilter)
			}
			got, got1, _ := EvaluateProfile(tt.args.profile, tt.args.Alert)
			if !reflect.DeepEqual(len(got), tt.expectedDecisionCount) {
				t.Errorf("EvaluateProfile() got = %+v, want %+v", got, tt.expectedDecisionCount)
			}
			if got1 != tt.expectedMatchStatus {
				t.Errorf("EvaluateProfile() got1 = %v, want %v", got1, tt.expectedMatchStatus)
			}
		})
	}
}
