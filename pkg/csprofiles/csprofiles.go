package csprofiles

import (
	"fmt"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Runtime struct {
	RuntimeFilters      []*vm.Program               `json:"-" yaml:"-"`
	DebugFilters        []*exprhelpers.ExprDebugger `json:"-" yaml:"-"`
	RuntimeDurationExpr *vm.Program                 `json:"-" yaml:"-"`
	DebugDurationExpr   *exprhelpers.ExprDebugger   `json:"-" yaml:"-"`
	Cfg                 csconfig.ProfileCfg         `json:"-" yaml:"-"`
}

var clog *log.Entry

func CompileProfile(profilesCfg []*csconfig.ProfileCfg) ([]*Runtime, error) {
	var err error
	profilesRuntime := []*Runtime{}

	for pIdx, profile := range profilesCfg {
		var runtimeFilter, runtimeDurationExpr *vm.Program
		var debugFilter, debugDurationExpr *exprhelpers.ExprDebugger

		profilesRuntime[pIdx].RuntimeFilters = make([]*vm.Program, len(profile.Filters))
		profilesRuntime[pIdx].DebugFilters = make([]*exprhelpers.ExprDebugger, len(profile.Filters))

		for fIdx, filter := range profile.Filters {
			if runtimeFilter, err = expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				return []*Runtime{}, errors.Wrapf(err, "Error compiling filter of %s", profile.Name)
			}
			profilesRuntime[pIdx].RuntimeFilters[fIdx] = runtimeFilter
			if debugFilter, err = exprhelpers.NewDebugger(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
				log.Debugf("Error compiling debug filter of %s : %s", profile.Name, err)
				// Don't fail if we can't compile the filter - for now
				//	return errors.Wrapf(err, "Error compiling debug filter of %s", profile.Name)
			}
			profilesRuntime[pIdx].DebugFilters[fIdx] = debugFilter
		}

		for _, decision := range profile.Decisions {
			if _, err := time.ParseDuration(*decision.Duration); err != nil {
				return []*Runtime{}, errors.Wrapf(err, "Error parsing duration '%s' of %s", *decision.Duration, profile.Name)
			}
		}

		if runtimeDurationExpr, err = expr.Compile(profile.DurationExpr, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
			return []*Runtime{}, errors.Wrapf(err, "Error compiling duration_expr of %s", profile.Name)
		}
		profilesRuntime[pIdx].RuntimeDurationExpr = runtimeDurationExpr
		if debugDurationExpr, err = exprhelpers.NewDebugger(profile.DurationExpr, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"Alert": &models.Alert{}}))); err != nil {
			log.Debugf("Error compiling debug duration_expr of %s : %s", profile.Name, err)
		}
		profilesRuntime[pIdx].DebugDurationExpr = debugDurationExpr

	}
	return profilesRuntime, nil
}

func GenerateDecisionFromProfile(profile *Runtime, Alert *models.Alert) ([]*models.Decision, error) {
	var decisions []*models.Decision

	if clog == nil {
		xlog := log.New()
		if err := types.ConfigureLogger(xlog); err != nil {
			log.Fatalf("While creating profiles-specific logger : %s", err)
		}
		xlog.SetLevel(log.TraceLevel)
		clog = xlog.WithFields(log.Fields{
			"type": "profile",
		})
	}

	for _, refDecision := range profile.Cfg.Decisions {
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
		if profile.Cfg.DurationExpr != "" {
			duration, err := expr.Run(profile.RuntimeDurationExpr, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
			if err != nil {
				log.Warningf("failed to run duration_expr : %v", err)
			}
			durationStr := fmt.Sprint(duration)
			if _, err := time.ParseDuration(durationStr); err != nil {
				log.Debugf("Failed to parse expr duration result '%s'", duration)
				*decision.Duration = *refDecision.Duration
			}
			*decision.Duration = durationStr
		}
		decision.Type = new(string)
		*decision.Type = *refDecision.Type

		/*for the others, let's populate it from the alert and its source*/
		decision.Value = new(string)
		*decision.Value = *Alert.Source.Value
		decision.Origin = new(string)
		*decision.Origin = "crowdsec"
		if refDecision.Origin != nil {
			*decision.Origin = fmt.Sprintf("%s/%s", *decision.Origin, *refDecision.Origin)
		}
		decision.Scenario = new(string)
		*decision.Scenario = *Alert.Scenario
		decisions = append(decisions, &decision)
	}
	return decisions, nil
}

//EvaluateProfile is going to evaluate an Alert against a profile to generate Decisions
func EvaluateProfile(profile *Runtime, Alert *models.Alert) ([]*models.Decision, bool, error) {
	var decisions []*models.Decision
	if clog == nil {
		xlog := log.New()
		if err := types.ConfigureLogger(xlog); err != nil {
			log.Fatalf("While creating profiles-specific logger : %s", err)
		}
		xlog.SetLevel(log.TraceLevel)
		clog = xlog.WithFields(log.Fields{
			"type": "profile",
		})
	}
	matched := false
	for eIdx, expression := range profile.RuntimeFilters {
		output, err := expr.Run(expression, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
		if err != nil {
			log.Warningf("failed to run whitelist expr : %v", err)
			return nil, matched, errors.Wrapf(err, "while running expression %s", profile.Cfg.Filters[eIdx])
		}
		switch out := output.(type) {
		case bool:
			if profile.Cfg.Debug != nil && *profile.Cfg.Debug {
				profile.DebugFilters[eIdx].Run(clog, out, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
			}
			if out {
				matched = true
				/*the expression matched, create the associated decision*/
				subdecisions, err := GenerateDecisionFromProfile(profile, Alert)
				if err != nil {
					return nil, matched, errors.Wrapf(err, "while generating decision from profile %s", profile.Cfg.Name)
				}

				decisions = append(decisions, subdecisions...)
			} else {
				log.Debugf("Profile %s filter is unsuccessful", profile.Cfg.Name)
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
