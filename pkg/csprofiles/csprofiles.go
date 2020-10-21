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

		if *decision.Scope == types.Ip {
			srcAddr := net.ParseIP(Alert.Source.IP)
			if srcAddr == nil {
				return nil, fmt.Errorf("can't parse ip %s", Alert.Source.IP)
			}
			decision.StartIP = int64(types.IP2Int(srcAddr))
			decision.EndIP = decision.StartIP
		} else if *decision.Scope == types.Range {
			/*here we're asked to ban a full range. let's keep in mind that it's not always possible :
			- the alert is about an IP, but the geolite enrichment failed
			- the alert is about an IP, but the geolite enrichment isn't present
			- the alert is about a range, in this case it should succeed
			*/
			if Alert.Source.Range != "" {
				srcAddr, srcRange, err := net.ParseCIDR(Alert.Source.Range)
				if err != nil {
					log.Warningf("Profile [%s] requires IP decision, but can't parse '%s' from '%s'",
						Profile.Name, *Alert.Source.Value, *Alert.Scenario)
					continue
				}
				decision.StartIP = int64(types.IP2Int(srcAddr))
				decision.EndIP = int64(types.IP2Int(types.LastAddress(srcRange)))
				decision.Value = new(string)
				*decision.Value = Alert.Source.Range
			} else {
				log.Warningf("Profile [%s] requires scope decision, but information is missing from %s", Profile.Name, *Alert.Scenario)
				continue
			}
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
