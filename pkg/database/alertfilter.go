package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func handleSimulatedFilter(filter map[string][]string, predicates *[]predicate.Alert) {
	/* the simulated filter is a bit different : if it's not present *or* set to false, specifically exclude records with simulated to true */
	if v, ok := filter["simulated"]; ok && v[0] == "false" {
		*predicates = append(*predicates, alert.SimulatedEQ(false))
	}
}

func handleOriginFilter(filter map[string][]string, predicates *[]predicate.Alert) {
	if _, ok := filter["origin"]; ok {
		filter["include_capi"] = []string{"true"}
	}
}

func handleScopeFilter(scope string, predicates *[]predicate.Alert) {
	if strings.ToLower(scope) == "ip" {
		scope = types.Ip
	} else if strings.ToLower(scope) == "range" {
		scope = types.Range
	}

	*predicates = append(*predicates, alert.SourceScopeEQ(scope))
}

func handleTimeFilters(param, value string, predicates *[]predicate.Alert) error {
	duration, err := ParseDuration(value)
	if err != nil {
		return fmt.Errorf("while parsing duration: %w", err)
	}

	timePoint := time.Now().UTC().Add(-duration)
	if timePoint.IsZero() {
		return fmt.Errorf("empty time now() - %s", timePoint.String())
	}

	switch param {
	case "since":
		*predicates = append(*predicates, alert.StartedAtGTE(timePoint))
	case "created_before":
		*predicates = append(*predicates, alert.CreatedAtLTE(timePoint))
	case "until":
		*predicates = append(*predicates, alert.StartedAtLTE(timePoint))
	}

	return nil
}

func handleIPv4Predicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPLTE(start_ip)),
			alert.HasDecisionsWith(decision.EndIPGTE(end_ip)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPGTE(start_ip)),
			alert.HasDecisionsWith(decision.EndIPLTE(end_ip)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
		))
	}
}

func handleIPv6Predicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			alert.Or(
				// decision.start_ip < query.start_ip
				alert.HasDecisionsWith(decision.StartIPLT(start_ip)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
					// decision.start_suffix <= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixLTE(start_sfx)),
				),
			),
			alert.Or(
				// decision.end_ip > query.end_ip
				alert.HasDecisionsWith(decision.EndIPGT(end_ip)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
					// decision.end_suffix >= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixGTE(end_sfx)),
				),
			),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			alert.Or(
				// decision.start_ip > query.start_ip
				alert.HasDecisionsWith(decision.StartIPGT(start_ip)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
					// decision.start_suffix >= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixGTE(start_sfx)),
				),
			),
			alert.Or(
				// decision.end_ip < query.end_ip
				alert.HasDecisionsWith(decision.EndIPLT(end_ip)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
					// decision.end_suffix <= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixLTE(end_sfx)),
				),
			),
		))
	}
}

func handleIPPredicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) error {
	if ip_sz == 4 {
		handleIPv4Predicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, predicates)
	} else if ip_sz == 16 {
		handleIPv6Predicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, predicates)
	} else if ip_sz != 0 {
		return errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}

	return nil
}

func handleIncludeCapiFilter(value string, predicates *[]predicate.Alert) error {
	if value == "false" {
		*predicates = append(*predicates, alert.And(
			// do not show alerts with active decisions having origin CAPI or lists
			alert.And(
				alert.Not(alert.HasDecisionsWith(decision.OriginEQ(types.CAPIOrigin))),
				alert.Not(alert.HasDecisionsWith(decision.OriginEQ(types.ListOrigin))),
			),
			alert.Not(
				alert.And(
					// do not show neither alerts with no decisions if the Source Scope is lists: or CAPI
					alert.Not(alert.HasDecisions()),
					alert.Or(
						alert.SourceScopeHasPrefix(types.ListOrigin+":"),
						alert.SourceScopeEQ(types.CommunityBlocklistPullSourceScope),
					),
				),
			),
		))
	} else if value != "true" {
		log.Errorf("invalid bool '%s' for include_capi", value)
	}

	return nil
}

func AlertPredicatesFromFilter(filter map[string][]string) ([]predicate.Alert, error) {
	predicates := make([]predicate.Alert, 0)

	var (
		err                                  error
		start_ip, start_sfx, end_ip, end_sfx int64
		hasActiveDecision                    bool
		ip_sz                                int
	)

	contains := true

	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/

	handleSimulatedFilter(filter, &predicates)
	handleOriginFilter(filter, &predicates)

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scope":
			handleScopeFilter(value[0], &predicates)
		case "value":
			predicates = append(predicates, alert.SourceValueEQ(value[0]))
		case "scenario":
			predicates = append(predicates, alert.HasDecisionsWith(decision.ScenarioEQ(value[0])))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, err
			}
		case "since", "created_before", "until":
			if err := handleTimeFilters(param, value[0], &predicates); err != nil {
				return nil, err
			}
		case "decision_type":
			predicates = append(predicates, alert.HasDecisionsWith(decision.TypeEQ(value[0])))
		case "origin":
			predicates = append(predicates, alert.HasDecisionsWith(decision.OriginEQ(value[0])))
		case "include_capi": // allows to exclude one or more specific origins
			if err = handleIncludeCapiFilter(value[0], &predicates); err != nil {
				return nil, err
			}
		case "has_active_decision":
			if hasActiveDecision, err = strconv.ParseBool(value[0]); err != nil {
				return nil, errors.Wrapf(ParseType, "'%s' is not a boolean: %s", value[0], err)
			}

			if hasActiveDecision {
				predicates = append(predicates, alert.HasDecisionsWith(decision.UntilGTE(time.Now().UTC())))
			} else {
				predicates = append(predicates, alert.Not(alert.HasDecisions()))
			}
		case "limit":
			continue
		case "sort":
			continue
		case "simulated":
			continue
		case "with_decisions":
			continue
		default:
			return nil, errors.Wrapf(InvalidFilter, "Filter parameter '%s' is unknown (=%s)", param, value[0])
		}
	}

	if err := handleIPPredicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, &predicates); err != nil {
		return nil, err
	}

	return predicates, nil
}

func BuildAlertRequestFromFilter(alerts *ent.AlertQuery, filter map[string][]string) (*ent.AlertQuery, error) {
	preds, err := AlertPredicatesFromFilter(filter)
	if err != nil {
		return nil, err
	}

	return alerts.Where(preds...), nil
}
