package csprofiles

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func GenerateDecisionFromProfile(Profile *csconfig.ProfileCfg, Alert *models.Alert) ([]*models.Decision, error) {
	var decisions []*models.Decision

	for _, refDecision := range Profile.Decisions {
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
		*decision.Duration = *refDecision.Duration
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

var clog *log.Entry

//EvaluateProfile is going to evaluate an Alert against a profile to generate Decisions
func EvaluateProfile(profile *csconfig.ProfileCfg, Alert *models.Alert) ([]*models.Decision, bool, error) {
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
	if !Alert.Remediation {
		return nil, matched, nil
	}
	for eIdx, expression := range profile.RuntimeFilters {
		output, err := expr.Run(expression, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
		if err != nil {
			log.Warningf("failed to run whitelist expr : %v", err)
			return nil, matched, errors.Wrapf(err, "while running expression %s", profile.Filters[eIdx])
		}
		switch out := output.(type) {
		case bool:
			if out {
				matched = true
				/*the expression matched, create the associated decision*/
				subdecisions, err := GenerateDecisionFromProfile(profile, Alert)
				if err != nil {
					return nil, matched, errors.Wrapf(err, "while generating decision from profile %s", profile.Name)
				}

				decisions = append(decisions, subdecisions...)
			} else {
				if profile.Debug != nil && *profile.Debug {
					profile.DebugFilters[eIdx].Run(clog, false, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
				}
				log.Debugf("Profile %s filter is unsuccessful", profile.Name)
				if profile.OnFailure == "break" {
					break
				}
			}

		default:
			return nil, matched, fmt.Errorf("unexpected type %t (%v) while running '%s'", output, output, profile.Filters[eIdx])

		}

	}
	return decisions, matched, nil
}
