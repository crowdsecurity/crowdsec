package csprofiles

import (
	"fmt"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Runtime struct {
	RuntimeFilters      []*vm.Program               `json:"-" yaml:"-"`
	DebugFilters        []*exprhelpers.ExprDebugger `json:"-" yaml:"-"`
	RuntimeDurationExpr *vm.Program                 `json:"-" yaml:"-"`
	DebugDurationExpr   *exprhelpers.ExprDebugger   `json:"-" yaml:"-"`
	Cfg                 *csconfig.ProfileCfg        `json:"-" yaml:"-"`
	Logger              *log.Entry                  `json:"-" yaml:"-"`
}

var defaultDuration = "4h"

func NewProfile(profilesCfg []*csconfig.ProfileCfg) ([]*Runtime, error) {
	var err error
	profilesRuntime := make([]*Runtime, 0)

	for _, profile := range profilesCfg {
		var runtimeFilter, runtimeDurationExpr *vm.Program
		var debugFilter, debugDurationExpr *exprhelpers.ExprDebugger
		runtime := &Runtime{}
		xlog := log.New()
		if err := types.ConfigureLogger(xlog); err != nil {
			log.Fatalf("While creating profiles-specific logger : %s", err)
		}
		xlog.SetLevel(log.InfoLevel)
		runtime.Logger = xlog.WithFields(log.Fields{
			"type": "profile",
			"name": profile.Name,
		})

		runtime.RuntimeFilters = make([]*vm.Program, len(profile.Filters))
		runtime.DebugFilters = make([]*exprhelpers.ExprDebugger, len(profile.Filters))
		runtime.Cfg = profile
		if runtime.Cfg.OnSuccess != "" && runtime.Cfg.OnSuccess != "continue" && runtime.Cfg.OnSuccess != "break" {
			return []*Runtime{}, fmt.Errorf("invalid 'on_success' for '%s': %s", profile.Name, runtime.Cfg.OnSuccess)
		}
		if runtime.Cfg.OnFailure != "" && runtime.Cfg.OnFailure != "continue" && runtime.Cfg.OnFailure != "break" && runtime.Cfg.OnFailure != "apply" {
			return []*Runtime{}, fmt.Errorf("invalid 'on_failure' for '%s' : %s", profile.Name, runtime.Cfg.OnFailure)
		}
		for fIdx, filter := range profile.Filters {

			if runtimeFilter, err = expr.Compile(filter, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
				return []*Runtime{}, errors.Wrapf(err, "error compiling filter of '%s'", profile.Name)
			}
			runtime.RuntimeFilters[fIdx] = runtimeFilter
			if profile.Debug != nil && *profile.Debug {
				if debugFilter, err = exprhelpers.NewDebugger(filter, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
					log.Debugf("Error compiling debug filter of %s : %s", profile.Name, err)
					// Don't fail if we can't compile the filter - for now
					//	return errors.Wrapf(err, "Error compiling debug filter of %s", profile.Name)
				}
				runtime.DebugFilters[fIdx] = debugFilter
				runtime.Logger.Logger.SetLevel(log.DebugLevel)
			}
		}

		if profile.DurationExpr != "" {
			if runtimeDurationExpr, err = expr.Compile(profile.DurationExpr, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
				return []*Runtime{}, errors.Wrapf(err, "error compiling duration_expr of %s", profile.Name)
			}

			runtime.RuntimeDurationExpr = runtimeDurationExpr
			if profile.Debug != nil && *profile.Debug {
				if debugDurationExpr, err = exprhelpers.NewDebugger(profile.DurationExpr, exprhelpers.GetExprOptions(map[string]interface{}{"Alert": &models.Alert{}})...); err != nil {
					log.Debugf("Error compiling debug duration_expr of %s : %s", profile.Name, err)
				}
				runtime.DebugDurationExpr = debugDurationExpr
			}
		}

		for _, decision := range profile.Decisions {
			if runtime.RuntimeDurationExpr == nil {
				if _, err := time.ParseDuration(*decision.Duration); err != nil {
					return []*Runtime{}, errors.Wrapf(err, "error parsing duration '%s' of %s", *decision.Duration, profile.Name)
				}
			}
		}

		profilesRuntime = append(profilesRuntime, runtime)
	}
	return profilesRuntime, nil
}

func (Profile *Runtime) GenerateDecisionFromProfile(Alert *models.Alert) ([]*models.Decision, error) {
	var decisions []*models.Decision

	for _, refDecision := range Profile.Cfg.Decisions {
		decision := models.Decision{}
		/*the reference decision from profile is in sumulated mode */
		if refDecision.Simulated != nil && *refDecision.Simulated {
			decision.Simulated = new(bool)
			*decision.Simulated = true
			/*the event is already in simulation mode */
		} else if Alert.Simulated != nil && *Alert.Simulated {
			decision.Simulated = new(bool)
			*decision.Simulated = true
		}
		/*If the profile specifies a scope, this will prevail.
		If not, we're going to get the scope from the source itself*/
		decision.Scope = new(string)
		if refDecision.Scope != nil && *refDecision.Scope != "" {
			*decision.Scope = *refDecision.Scope
		} else {
			*decision.Scope = *Alert.Source.Scope
		}
		/*some fields are populated from the reference object : duration, scope, type*/
		decision.Duration = new(string)
		if Profile.Cfg.DurationExpr != "" && Profile.RuntimeDurationExpr != nil {
			duration, err := expr.Run(Profile.RuntimeDurationExpr, map[string]interface{}{"Alert": Alert})
			if err != nil {
				Profile.Logger.Warningf("Failed to run duration_expr : %v", err)
				*decision.Duration = *refDecision.Duration
			} else {
				durationStr := fmt.Sprint(duration)
				if _, err := time.ParseDuration(durationStr); err != nil {
					Profile.Logger.Warningf("Failed to parse expr duration result '%s'", duration)
					*decision.Duration = *refDecision.Duration
				} else {
					*decision.Duration = durationStr
				}
			}
		} else {
			if refDecision.Duration == nil {
				*decision.Duration = defaultDuration
			}
			*decision.Duration = *refDecision.Duration
		}

		decision.Type = new(string)
		*decision.Type = *refDecision.Type

		/*for the others, let's populate it from the alert and its source*/
		decision.Value = new(string)
		*decision.Value = *Alert.Source.Value
		decision.Origin = new(string)
		*decision.Origin = types.CrowdSecOrigin
		if refDecision.Origin != nil {
			*decision.Origin = fmt.Sprintf("%s/%s", *decision.Origin, *refDecision.Origin)
		}
		decision.Scenario = new(string)
		*decision.Scenario = *Alert.Scenario
		decisions = append(decisions, &decision)
	}
	return decisions, nil
}

// EvaluateProfile is going to evaluate an Alert against a profile to generate Decisions
func (Profile *Runtime) EvaluateProfile(Alert *models.Alert) ([]*models.Decision, bool, error) {
	var decisions []*models.Decision

	matched := false
	for eIdx, expression := range Profile.RuntimeFilters {
		output, err := expr.Run(expression, map[string]interface{}{"Alert": Alert})
		if err != nil {
			Profile.Logger.Warningf("failed to run whitelist expr : %v", err)
			return nil, matched, errors.Wrapf(err, "while running expression %s", Profile.Cfg.Filters[eIdx])
		}
		switch out := output.(type) {
		case bool:
			if Profile.Cfg.Debug != nil && *Profile.Cfg.Debug {
				Profile.DebugFilters[eIdx].Run(Profile.Logger, out, map[string]interface{}{"Alert": Alert})
			}
			if out {
				matched = true
				/*the expression matched, create the associated decision*/
				subdecisions, err := Profile.GenerateDecisionFromProfile(Alert)
				if err != nil {
					return nil, matched, errors.Wrapf(err, "while generating decision from profile %s", Profile.Cfg.Name)
				}

				decisions = append(decisions, subdecisions...)
			} else {
				Profile.Logger.Debugf("Profile %s filter is unsuccessful", Profile.Cfg.Name)
				if Profile.Cfg.OnFailure == "break" {
					break
				}
			}

		default:
			return nil, matched, fmt.Errorf("unexpected type %t (%v) while running '%s'", output, output, Profile.Cfg.Filters[eIdx])

		}

	}

	return decisions, matched, nil
}
