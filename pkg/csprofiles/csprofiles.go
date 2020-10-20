package csprofiles

import (
	"fmt"
	"net"

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
		/*some fields are populated from the reference object : duration, scope, type*/
		decision.Duration = new(string)
		*decision.Duration = *refDecision.Duration
		decision.Scope = new(string)
		*decision.Scope = *refDecision.Scope
		decision.Type = new(string)
		*decision.Type = *refDecision.Type

		/*for the others, let's populate it from the alert and its source*/
		decision.Value = new(string)
		*decision.Value = *Alert.Source.Value

		if *decision.Scope == types.Ip {
			srcAddr := net.ParseIP(Alert.Source.IP)
			if srcAddr == nil {
				return nil, fmt.Errorf("can't parse ip %s", Alert.Source.IP)
			}
			decision.StartIP = int64(types.IP2Int(srcAddr))
			decision.EndIP = decision.StartIP
		} else if *Alert.Source.Scope == types.Range {
			srcAddr, srcRange, err := net.ParseCIDR(*Alert.Source.Value)
			if err != nil {
				return nil, fmt.Errorf("can't parse range %s", *Alert.Source.Value)
			}
			decision.StartIP = int64(types.IP2Int(srcAddr))
			decision.EndIP = int64(types.IP2Int(types.LastAddress(srcRange)))
		}
		decision.Origin = new(string)
		*decision.Origin = "crowdsec"
		if refDecision.Origin != nil {
			*decision.Origin = fmt.Sprintf("%s/%s", *decision.Origin, *refDecision.Origin)
		}
		decision.Scenario = new(string)
		*decision.Scenario = *Alert.Scenario
		log.Printf("%s %s decision : %s %s", *decision.Scope, *decision.Value, *decision.Duration, *decision.Type)
		decisions = append(decisions, &decision)
	}
	return decisions, nil
}

var clog *log.Entry

//EvaluateProfiles is going to evaluate an Alert against a set of profiles to generate Decisions
func EvaluateProfiles(Profiles []*csconfig.ProfileCfg, Alert *models.Alert) ([]*models.Decision, error) {
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

	if !Alert.Remediation {
		return nil, nil
	}
PROFILE_LOOP:
	for _, profile := range Profiles {
		for eIdx, expression := range profile.RuntimeFilters {
			output, err := expr.Run(expression, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
			if err != nil {
				log.Warningf("failed to run whitelist expr : %v", err)
				return nil, errors.Wrapf(err, "while running expression %s", profile.Filters[eIdx])
			}
			switch out := output.(type) {
			case bool:
				if out {
					/*the expression matched, create the associated decision*/
					subdecisions, err := GenerateDecisionFromProfile(profile, Alert)
					if err != nil {
						return nil, errors.Wrapf(err, "while generating decision from profile %s", profile.Name)
					}
					decisions = append(decisions, subdecisions...)
				} else {
					if profile.Debug != nil && *profile.Debug {
						profile.DebugFilters[eIdx].Run(clog, false, exprhelpers.GetExprEnv(map[string]interface{}{"Alert": Alert}))
					}
					log.Debugf("Profile %s filter is unsuccessful", profile.Name)
					if profile.OnFailure == "break" {
						break PROFILE_LOOP
					}
				}
			default:
				return nil, fmt.Errorf("unexpected type %t (%v) while running '%s'", output, output, profile.Filters[eIdx])

			}
			if profile.OnSuccess == "break" {
				break PROFILE_LOOP
			}
		}
	}
	return decisions, nil
}
