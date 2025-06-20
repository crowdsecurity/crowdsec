package database

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func applyDecisionFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	var (
		err                                  error
		start_ip, start_sfx, end_ip, end_sfx int64
		ip_sz                                int
	)

	contains := true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
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
				return nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
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
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		case "limit":
			limit, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid limit value : %s", err)
			}

			query = query.Limit(limit)
		case "offset":
			offset, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid offset value : %s", err)
			}

			query = query.Offset(offset)
		case "id_gt":
			id, err := strconv.Atoi(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid id_gt value : %s", err)
			}

			query = query.Where(decision.IDGT(id))
		}
	}

	query, err = decisionIPFilter(query, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	if err != nil {
		return nil, fmt.Errorf("fail to apply StartIpEndIpFilter: %w", err)
	}

	return query, nil
}

func decisionIPv4Filter(decisions *ent.DecisionQuery, contains bool, ip_sz int, start_ip int64, start_sfx int64, end_ip int64, end_sfx int64) (*ent.DecisionQuery, error) {
	if contains {
		/*Decision contains {start_ip,end_ip}*/
		return decisions.Where(decision.And(
			decision.StartIPLTE(start_ip),
			decision.EndIPGTE(end_ip),
			decision.IPSizeEQ(int64(ip_sz)))), nil
	}

	/*Decision is contained within {start_ip,end_ip}*/
	return decisions.Where(decision.And(
		decision.StartIPGTE(start_ip),
		decision.EndIPLTE(end_ip),
		decision.IPSizeEQ(int64(ip_sz)))), nil
}

func decisionIPv6Filter(decisions *ent.DecisionQuery, contains bool, ip_sz int, start_ip int64, start_sfx int64, end_ip int64, end_sfx int64) (*ent.DecisionQuery, error) {
	/*decision contains {start_ip,end_ip}*/
	if contains {
		return decisions.Where(decision.And(
			// matching addr size
			decision.IPSizeEQ(int64(ip_sz)),
			decision.Or(
				// decision.start_ip < query.start_ip
				decision.StartIPLT(start_ip),
				decision.And(
					// decision.start_ip == query.start_ip
					decision.StartIPEQ(start_ip),
					// decision.start_suffix <= query.start_suffix
					decision.StartSuffixLTE(start_sfx),
				)),
			decision.Or(
				// decision.end_ip > query.end_ip
				decision.EndIPGT(end_ip),
				decision.And(
					// decision.end_ip == query.end_ip
					decision.EndIPEQ(end_ip),
					// decision.end_suffix >= query.end_suffix
					decision.EndSuffixGTE(end_sfx),
				),
			),
		)), nil
	}

	/*decision is contained within {start_ip,end_ip}*/
	return decisions.Where(decision.And(
		// matching addr size
		decision.IPSizeEQ(int64(ip_sz)),
		decision.Or(
			// decision.start_ip > query.start_ip
			decision.StartIPGT(start_ip),
			decision.And(
				// decision.start_ip == query.start_ip
				decision.StartIPEQ(start_ip),
				// decision.start_suffix >= query.start_suffix
				decision.StartSuffixGTE(start_sfx),
			)),
		decision.Or(
			// decision.end_ip < query.end_ip
			decision.EndIPLT(end_ip),
			decision.And(
				// decision.end_ip == query.end_ip
				decision.EndIPEQ(end_ip),
				// decision.end_suffix <= query.end_suffix
				decision.EndSuffixLTE(end_sfx),
			),
		),
	)), nil
}

func decisionIPFilter(decisions *ent.DecisionQuery, contains bool, ip_sz int, start_ip int64, start_sfx int64, end_ip int64, end_sfx int64) (*ent.DecisionQuery, error) {
	switch ip_sz {
	case 4:
		return decisionIPv4Filter(decisions, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	case 16:
		return decisionIPv6Filter(decisions, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	case 0:
		return decisions, nil
	default:
		return nil, errors.Wrapf(InvalidFilter, "unknown ip size %d", ip_sz)
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
