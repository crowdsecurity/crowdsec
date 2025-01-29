package csprofiles

import (
	"fmt"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Runtime struct {
	RuntimeFilters      []*vm.Program        `json:"-" yaml:"-"`
	RuntimeDurationExpr *vm.Program          `json:"-" yaml:"-"`
	Cfg                 *csconfig.ProfileCfg `json:"-" yaml:"-"`
	Logger              *log.Entry           `json:"-" yaml:"-"`
}

const defaultDuration = "4h"

func NewProfile(profilesCfg []*csconfig.ProfileCfg) ([]*Runtime, error) {
	var err error

	profilesRuntime := make([]*Runtime, 0)

	for _, profile := range profilesCfg {
		var runtimeFilter, runtimeDurationExpr *vm.Program

		runtime := &Runtime{}

		xlog := log.New()
		if err := types.ConfigureLogger(xlog); err != nil {
			return nil, fmt.Errorf("while configuring profiles-specific logger: %w", err)
		}

		xlog.SetLevel(log.InfoLevel)
		runtime.Logger = xlog.WithFields(log.Fields{
			"type": "profile",
			"name": profile.Name,
		})

		runtime.RuntimeFilters = make([]*vm.Program, len(profile.Filters))
		runtime.Cfg = profile

		if runtime.Cfg.OnSuccess != "" && runtime.Cfg.OnSuccess != "continue" && runtime.Cfg.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for '%s': %s", profile.Name, runtime.Cfg.OnSuccess)
		}

		if runtime.Cfg.OnFailure != "" && runtime.Cfg.OnFailure != "continue" && runtime.Cfg.OnFailure != "break" && runtime.Cfg.OnFailure != "apply" {
			return nil, fmt.Errorf("invalid 'on_failure' for '%s' : %s", profile.Name, runtime.Cfg.OnFailure)
		}

		for fIdx, filter := range profile.Filters {
			if runtimeFilter, err = expr.Compile(filter, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
				return nil, fmt.Errorf("error compiling filter of '%s': %w", profile.Name, err)
			}

			runtime.RuntimeFilters[fIdx] = runtimeFilter
			if profile.Debug != nil && *profile.Debug {
				runtime.Logger.Logger.SetLevel(log.DebugLevel)
			}
		}

		if profile.DurationExpr != "" {
			if runtimeDurationExpr, err = expr.Compile(profile.DurationExpr, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
				return nil, fmt.Errorf("error compiling duration_expr of %s: %w", profile.Name, err)
			}

			runtime.RuntimeDurationExpr = runtimeDurationExpr
		}

		for _, decision := range profile.Decisions {
			if runtime.RuntimeDurationExpr == nil {
				var duration string
				if decision.Duration != nil {
					duration = *decision.Duration
				} else {
					runtime.Logger.Warningf("No duration specified for %s, using default duration %s", profile.Name, defaultDuration)
					duration = defaultDuration
				}

				if _, err := time.ParseDuration(duration); err != nil {
					return nil, fmt.Errorf("error parsing duration '%s' of %s: %w", duration, profile.Name, err)
				}
			}
		}

		profilesRuntime = append(profilesRuntime, runtime)
	}

	return profilesRuntime, nil
}

func (profile *Runtime) GenerateDecisionFromProfile(alert *models.Alert) ([]*models.Decision, error) {
	var decisions []*models.Decision

	for _, refDecision := range profile.Cfg.Decisions {
		decision := models.Decision{}
		/*the reference decision from profile is in simulated mode */
		if refDecision.Simulated != nil && *refDecision.Simulated {
			decision.Simulated = new(bool)
			*decision.Simulated = true
			/*the event is already in simulation mode */
		} else if alert.Simulated != nil && *alert.Simulated {
			decision.Simulated = new(bool)
			*decision.Simulated = true
		}
		/*If the profile specifies a scope, this will prevail.
		If not, we're going to get the scope from the source itself*/
		decision.Scope = new(string)
		if refDecision.Scope != nil && *refDecision.Scope != "" {
			*decision.Scope = *refDecision.Scope
		} else {
			*decision.Scope = *alert.Source.Scope
		}
		/*some fields are populated from the reference object : duration, scope, type*/

		decision.Duration = new(string)
		if refDecision.Duration != nil {
			*decision.Duration = *refDecision.Duration
		}

		if profile.Cfg.DurationExpr != "" && profile.RuntimeDurationExpr != nil {
			profileDebug := false
			if profile.Cfg.Debug != nil && *profile.Cfg.Debug {
				profileDebug = true
			}

			duration, err := exprhelpers.Run(profile.RuntimeDurationExpr, map[string]interface{}{"Alert": alert}, profile.Logger, profileDebug)
			if err != nil {
				profile.Logger.Warningf("Failed to run duration_expr : %v", err)
			} else {
				durationStr := fmt.Sprint(duration)
				if _, err := time.ParseDuration(durationStr); err != nil {
					profile.Logger.Warningf("Failed to parse expr duration result '%s'", duration)
				} else {
					*decision.Duration = durationStr
				}
			}
		}

		decision.Type = new(string)
		*decision.Type = *refDecision.Type

		/*for the others, let's populate it from the alert and its source*/
		decision.Value = new(string)
		*decision.Value = *alert.Source.Value
		decision.Origin = new(string)
		*decision.Origin = types.CrowdSecOrigin

		if refDecision.Origin != nil {
			*decision.Origin = fmt.Sprintf("%s/%s", *decision.Origin, *refDecision.Origin)
		}

		decision.Scenario = new(string)
		*decision.Scenario = *alert.Scenario
		decisions = append(decisions, &decision)
	}

	return decisions, nil
}

// EvaluateProfile is going to evaluate an Alert against a profile to generate Decisions
func (profile *Runtime) EvaluateProfile(alert *models.Alert) ([]*models.Decision, bool, error) {
	var decisions []*models.Decision

	matched := false

	for eIdx, expression := range profile.RuntimeFilters {
		debugProfile := false
		if profile.Cfg.Debug != nil && *profile.Cfg.Debug {
			debugProfile = true
		}

		output, err := exprhelpers.Run(expression, map[string]interface{}{"Alert": alert}, profile.Logger, debugProfile)
		if err != nil {
			profile.Logger.Warningf("failed to run profile expr for %s: %v", profile.Cfg.Name, err)
			return nil, matched, fmt.Errorf("while running expression %s: %w", profile.Cfg.Filters[eIdx], err)
		}

		switch out := output.(type) {
		case bool:
			if out {
				matched = true
				/*the expression matched, create the associated decision*/
				subdecisions, err := profile.GenerateDecisionFromProfile(alert)
				if err != nil {
					return nil, matched, fmt.Errorf("while generating decision from profile %s: %w", profile.Cfg.Name, err)
				}

				decisions = append(decisions, subdecisions...)
			} else {
				profile.Logger.Debugf("Profile %s filter is unsuccessful", profile.Cfg.Name)

				if profile.Cfg.OnFailure == "break" {
					break
				}
			}

		default:
			return nil, matched, fmt.Errorf("unexpected type %t (%v) while running '%s'", output, output, profile.Cfg.Filters[eIdx])
		}
	}

	return decisions, matched, nil
}
