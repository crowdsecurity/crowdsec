package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
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

func handleOriginFilter(filter map[string][]string) {
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
	// crowsdec now always sends duration without days, but we allow them for
	// compatibility with other tools
	duration, err := cstime.ParseDurationWithDays(value)
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

func handleAlertIPv4Predicates(rng csnet.Range, contains bool, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPLTE(rng.Start.Addr)),
			alert.HasDecisionsWith(decision.EndIPGTE(rng.End.Addr)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(rng.Size()))),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPGTE(rng.Start.Addr)),
			alert.HasDecisionsWith(decision.EndIPLTE(rng.End.Addr)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(rng.Size()))),
		))
	}
}

func handleAlertIPv6Predicates(rng csnet.Range, contains bool, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(rng.Size()))),
			alert.Or(
				// decision.start_ip < query.start_ip
				alert.HasDecisionsWith(decision.StartIPLT(rng.Start.Addr)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(rng.Start.Addr)),
					// decision.start_suffix <= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixLTE(rng.Start.Sfx)),
				),
			),
			alert.Or(
				// decision.end_ip > query.end_ip
				alert.HasDecisionsWith(decision.EndIPGT(rng.End.Addr)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(rng.End.Addr)),
					// decision.end_suffix >= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixGTE(rng.End.Sfx)),
				),
			),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(rng.Size()))),
			alert.Or(
				// decision.start_ip > query.start_ip
				alert.HasDecisionsWith(decision.StartIPGT(rng.Start.Addr)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(rng.Start.Addr)),
					// decision.start_suffix >= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixGTE(rng.Start.Sfx)),
				),
			),
			alert.Or(
				// decision.end_ip < query.end_ip
				alert.HasDecisionsWith(decision.EndIPLT(rng.End.Addr)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(rng.End.Addr)),
					// decision.end_suffix <= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixLTE(rng.End.Sfx)),
				),
			),
		))
	}
}

func handleAlertIPPredicates(rng csnet.Range, contains bool, predicates *[]predicate.Alert) error {
	switch rng.Size() {
	case 4:
		handleAlertIPv4Predicates(rng, contains, predicates)
		return nil
	case 16:
		handleAlertIPv6Predicates(rng, contains, predicates)
		return nil
	case 0:
		return nil
	default:
		return fmt.Errorf("unknown ip size %d: %w", rng.Size(), InvalidFilter)
	}
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
		log.Errorf("invalid bool %q for include_capi", value)
	}

	return nil
}

func alertPredicatesFromFilter(filter map[string][]string) ([]predicate.Alert, error) {
	predicates := make([]predicate.Alert, 0)

	var (
		err               error
		hasActiveDecision bool
		rng               csnet.Range
	)

	contains := true

	// if contains is true, return bans that *contains* the given value (value is the inner)
	// else, return bans that are *contained* by the given value (value is the outer)

	handleSimulatedFilter(filter, &predicates)
	handleOriginFilter(filter)

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, fmt.Errorf("invalid contains value: %w: %w", err, InvalidFilter)
			}
		case "scope":
			handleScopeFilter(value[0], &predicates)
		case "value":
			predicates = append(predicates, alert.SourceValueEQ(value[0]))
		case "scenario":
			predicates = append(predicates, alert.Or(
				alert.ScenarioEQ(value[0]), // match alerts with no decisions
				alert.HasDecisionsWith(decision.ScenarioEQ(value[0])),
			))
		case "ip", "range":
			rng, err = csnet.NewRange(value[0])
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
				return nil, fmt.Errorf("'%s' is not a boolean: %w: %w", value[0], err, ParseType)
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
			return nil, fmt.Errorf("filter parameter '%s' is unknown (=%s): %w", param, value[0], InvalidFilter)
		}
	}

	if err := handleAlertIPPredicates(rng, contains, &predicates); err != nil {
		return nil, err
	}

	return predicates, nil
}

func applyAlertFilter(alerts *ent.AlertQuery, filter map[string][]string) (*ent.AlertQuery, error) {
	preds, err := alertPredicatesFromFilter(filter)
	if err != nil {
		return nil, err
	}

	return alerts.Where(preds...), nil
}
