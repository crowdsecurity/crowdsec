package database

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func applyDecisionFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	var (
		rng csnet.Range
		err error
	)

	contains := true
	/*if contains is true, return bans that *contain* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/

	/*the simulated filter is a bit different : if it's not present *or* set to false, specifically exclude records with simulated to true */
	if v, ok := filter["simulated"]; ok {
		if v[0] == "false" {
			query = query.Where(decision.SimulatedEQ(false))
		}

		delete(filter, "simulated")
	} else {
		query = query.Where(decision.SimulatedEQ(false))
	}

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, fmt.Errorf("invalid contains value: %w: %w", err, InvalidFilter)
			}
		case "scopes", "scope": // Swagger mentions both of them, let's just support both to make sure we don't break anything
			scopes := strings.Split(value[0], ",")
			for i, scope := range scopes {
				switch strings.ToLower(scope) {
				case "ip":
					scopes[i] = types.Ip
				case "range":
					scopes[i] = types.Range
				case "country":
					scopes[i] = types.Country
				case "as":
					scopes[i] = types.AS
				}
			}

			query = query.Where(decision.ScopeIn(scopes...))
		case "value":
			query = query.Where(decision.ValueEQ(value[0]))
		case "type":
			query = query.Where(decision.TypeEQ(value[0]))
		case "origins":
			query = query.Where(
				decision.OriginIn(strings.Split(value[0], ",")...),
			)
		case "scenarios_containing":
			predicates := decisionPredicatesFromStr(value[0], decision.ScenarioContainsFold)
			query = query.Where(decision.Or(predicates...))
		case "scenarios_not_containing":
			predicates := decisionPredicatesFromStr(value[0], decision.ScenarioContainsFold)
			query = query.Where(decision.Not(
				decision.Or(
					predicates...,
				),
			))
		case "ip", "range":
			rng, err = csnet.NewRange(value[0])
			if err != nil {
				return nil, fmt.Errorf("unable to convert '%s' to int: %w: %w", value[0], err, InvalidIPOrRange)
			}
		case "limit":
			limit, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, fmt.Errorf("invalid limit value: %w: %w", err, InvalidFilter)
			}

			query = query.Limit(limit)
		case "offset":
			offset, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, fmt.Errorf("invalid offset value: %w: %w", err, InvalidFilter)
			}

			query = query.Offset(offset)
		case "id_gt":
			id, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, fmt.Errorf("invalid id_gt value: %w: %w", err, InvalidFilter)
			}

			query = query.Where(decision.IDGT(id))
		}
	}

	query, err = decisionIPFilter(query, contains, rng)
	if err != nil {
		return nil, fmt.Errorf("fail to apply StartIpEndIpFilter: %w", err)
	}

	return query, nil
}

func decisionIPv4Filter(decisions *ent.DecisionQuery, contains bool, rng csnet.Range) (*ent.DecisionQuery, error) {
	if contains {
		// Decision contains {start_ip,end_ip}
		return decisions.Where(decision.And(
			decision.StartIPLTE(rng.Start.Addr),
			decision.EndIPGTE(rng.End.Addr),
			decision.IPSizeEQ(int64(rng.Size())))), nil
	}

	// Decision is contained within {start_ip,end_ip}
	return decisions.Where(decision.And(
		decision.StartIPGTE(rng.Start.Addr),
		decision.EndIPLTE(rng.End.Addr),
		decision.IPSizeEQ(int64(rng.Size())))), nil
}

func decisionIPv6Filter(decisions *ent.DecisionQuery, contains bool, rng csnet.Range) (*ent.DecisionQuery, error) {
	// decision contains {start_ip,end_ip}
	if contains {
		return decisions.Where(decision.And(
			// matching addr size
			decision.IPSizeEQ(int64(rng.Size())),
			decision.Or(
				// decision.start_ip < query.start_ip
				decision.StartIPLT(rng.Start.Addr),
				decision.And(
					// decision.start_ip == query.start_ip
					decision.StartIPEQ(rng.Start.Addr),
					// decision.start_suffix <= query.start_suffix
					decision.StartSuffixLTE(rng.Start.Sfx),
				)),
			decision.Or(
				// decision.end_ip > query.end_ip
				decision.EndIPGT(rng.End.Addr),
				decision.And(
					// decision.end_ip == query.end_ip
					decision.EndIPEQ(rng.End.Addr),
					// decision.end_suffix >= query.end_suffix
					decision.EndSuffixGTE(rng.End.Sfx),
				),
			),
		)), nil
	}

	// decision is contained within {start_ip,end_ip}
	return decisions.Where(decision.And(
		// matching addr size
		decision.IPSizeEQ(int64(rng.Size())),
		decision.Or(
			// decision.start_ip > query.start_ip
			decision.StartIPGT(rng.Start.Addr),
			decision.And(
				// decision.start_ip == query.start_ip
				decision.StartIPEQ(rng.Start.Addr),
				// decision.start_suffix >= query.start_suffix
				decision.StartSuffixGTE(rng.Start.Sfx),
			)),
		decision.Or(
			// decision.end_ip < query.end_ip
			decision.EndIPLT(rng.End.Addr),
			decision.And(
				// decision.end_ip == query.end_ip
				decision.EndIPEQ(rng.End.Addr),
				// decision.end_suffix <= query.end_suffix
				decision.EndSuffixLTE(rng.End.Sfx),
			),
		),
	)), nil
}

func decisionIPFilter(decisions *ent.DecisionQuery, contains bool, rng csnet.Range) (*ent.DecisionQuery, error) {
	switch rng.Size() {
	case 4:
		return decisionIPv4Filter(decisions, contains, rng)
	case 16:
		return decisionIPv6Filter(decisions, contains, rng)
	case 0:
		return decisions, nil
	default:
		return nil, fmt.Errorf("unknown ip size %d: %w", rng.Size(), InvalidFilter)
	}
}

func decisionPredicatesFromStr(s string, predicateFunc func(string) predicate.Decision) []predicate.Decision {
	words := strings.Split(s, ",")
	predicates := make([]predicate.Decision, len(words))

	for i, word := range words {
		predicates[i] = predicateFunc(word)
	}

	return predicates
}
