package database

import (
	"fmt"
	"strings"
	"time"

	"strconv"

	"entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
)

type DecisionsByScenario struct {
	Scenario string
	Count    int
	Origin   string
	Type     string
}

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, []*sql.Predicate, error) {

	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains bool = true

	// contains == true -> return bans that *contain* the given value (value is the inner)
	// contains == false or missing -> return bans *contained* in the given value (value is the outer)

	// simulated == true -> include simulated rows
	// simulated == false or missing -> exclude simulated rows

	if v, ok := filter["simulated"]; ok {
		if v[0] == "false" {
			query = query.Where(decision.SimulatedEQ(false))
		}
		delete(filter, "simulated")
	} else {
		query = query.Where(decision.SimulatedEQ(false))
	}
	t := sql.Table(decision.Table)
	joinPredicate := make([]*sql.Predicate, 0)
	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scopes":
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
			origins := strings.Split(value[0], ",")
			originsContainsPredicate := make([]*sql.Predicate, 0)
			for _, origin := range origins {
				pred := sql.EqualFold(t.C(decision.FieldOrigin), origin)
				originsContainsPredicate = append(originsContainsPredicate, pred)
			}
			joinPredicate = append(joinPredicate, sql.Or(originsContainsPredicate...))
		case "scenarios_containing":
			predicates := decisionPredicatesFromStr(value[0], decision.ScenarioContainsFold)
			query = query.Where(decision.Or(predicates...))

			scenarios := strings.Split(value[0], ",")
			scenariosContainsPredicate := make([]*sql.Predicate, 0)
			for _, scenario := range scenarios {
				pred := sql.ContainsFold(t.C(decision.FieldScenario), scenario)
				scenariosContainsPredicate = append(scenariosContainsPredicate, pred)
			}
			joinPredicate = append(joinPredicate, sql.Or(scenariosContainsPredicate...))
		case "scenarios_not_containing":
			predicates := decisionPredicatesFromStr(value[0], decision.ScenarioContainsFold)
			query = query.Where(decision.Not(
				decision.Or(
					predicates...,
				),
			))
			scenarios := strings.Split(value[0], ",")
			scenariosContainsPredicate := make([]*sql.Predicate, 0)
			for _, scenario := range scenarios {
				pred := sql.ContainsFold(t.C(decision.FieldScenario), scenario)
				scenariosContainsPredicate = append(scenariosContainsPredicate, sql.Not(pred))
			}
			joinPredicate = append(joinPredicate, sql.Or(scenariosContainsPredicate...))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		}
	}

	query, err = applyStartIpEndIpFilter(query, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "fail to apply StartIpEndIpFilter")
	}
	return query, joinPredicate, nil
}

func (c *Client) QueryDecisionWithFilter(filter map[string][]string) ([]*ent.Decision, error) {
	var data []*ent.Decision
	var err error

	decisions := c.Ent.Decision.Query().
		Where(decision.UntilGTE(time.Now().UTC()))

	decisions, _, err = BuildDecisionRequestWithFilter(decisions, filter)
	if err != nil {
		return []*ent.Decision{}, err
	}

	err = decisions.Select(
		decision.FieldID,
		decision.FieldUntil,
		decision.FieldScenario,
		decision.FieldType,
		decision.FieldStartIP,
		decision.FieldEndIP,
		decision.FieldValue,
		decision.FieldScope,
		decision.FieldOrigin,
	).Scan(c.CTX, &data)
	if err != nil {
		c.Log.Warningf("QueryDecisionWithFilter : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "query decision failed")
	}

	return data, nil
}

func (c *Client) QueryAllDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)
	query, _, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}

	//Order is *very* important, the dedup assumes that decisions are sorted per IP and per time left
	data, err := query.Order(ent.Asc(decision.FieldValue), ent.Desc(decision.FieldUntil)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}

	return data, nil
}

func (c *Client) QueryDecisionCountByScenario(filters map[string][]string) ([]*DecisionsByScenario, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)
	query, _, err := BuildDecisionRequestWithFilter(query, filters)

	if err != nil {
		c.Log.Warningf("QueryDecisionCountByScenario : %s", err)
		return nil, errors.Wrap(QueryFail, "count all decisions with filters")
	}

	var r []*DecisionsByScenario

	err = query.GroupBy(decision.FieldScenario, decision.FieldOrigin, decision.FieldType).Aggregate(ent.Count()).Scan(c.CTX, &r)

	if err != nil {
		c.Log.Warningf("QueryDecisionCountByScenario : %s", err)
		return nil, errors.Wrap(QueryFail, "count all decisions with filters")
	}

	return r, nil
}

func (c *Client) QueryExpiredDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	now := time.Now().UTC()
	query := c.Ent.Decision.Query().Where(
		decision.UntilLT(time.Now().UTC()),
	)
	query, predicates, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get expired decisions with filters")
	}
	query = query.Where(func(s *sql.Selector) {
		t := sql.Table(decision.Table)

		subQuery := sql.Select(t.C(decision.FieldValue)).From(t).Where(sql.GT(t.C(decision.FieldUntil), now))
		for _, predicate := range predicates {
			subQuery.Where(predicate)
		}
		s.Where(
			sql.NotIn(
				s.C(decision.FieldValue),
				subQuery,
			),
		)
	})

	data, err := query.Order(ent.Asc(decision.FieldValue), ent.Desc(decision.FieldUntil)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}

	return data, nil
}

func (c *Client) QueryExpiredDecisionsSinceWithFilters(since time.Time, filters map[string][]string) ([]*ent.Decision, error) {
	now := time.Now().UTC()

	query := c.Ent.Decision.Query().Where(
		decision.UntilLT(now),
		decision.UntilGT(since),
	)
	query, predicates, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	query = query.Where(func(s *sql.Selector) {
		t := sql.Table(decision.Table)

		subQuery := sql.Select(t.C(decision.FieldValue)).From(t).Where(sql.GT(t.C(decision.FieldUntil), now))
		for _, predicate := range predicates {
			subQuery.Where(predicate)
		}
		s.Where(
			sql.NotIn(
				s.C(decision.FieldValue),
				subQuery,
			),
		)
	})

	data, err := query.Order(ent.Asc(decision.FieldValue), ent.Desc(decision.FieldUntil)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	return data, nil
}

func (c *Client) QueryNewDecisionsSinceWithFilters(since time.Time, filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.CreatedAtGT(since),
		decision.UntilGT(time.Now().UTC()),
	)
	query, _, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("BuildDecisionRequestWithFilter : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	//Order is *very* important, the dedup assumes that decisions are sorted per IP and per time left
	data, err := query.Order(ent.Asc(decision.FieldValue), ent.Desc(decision.FieldUntil)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrapf(QueryFail, "new decisions since '%s'", since.String())
	}
	return data, nil
}

func (c *Client) DeleteDecisionById(decisionId int) error {
	err := c.Ent.Decision.DeleteOneID(decisionId).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteDecisionById : %s", err)
		return errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionId)
	}
	return nil
}

func (c *Client) DeleteDecisionsWithFilter(filter map[string][]string) (string, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains bool = true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer) */

	decisions := c.Ent.Decision.Delete()
	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return "0", errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scope":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.ValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return "0", errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		default:
			return "0", errors.Wrap(InvalidFilter, fmt.Sprintf("'%s' doesn't exist", param))
		}
	}
	if ip_sz == 4 {
		if contains { /*decision contains {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPLTE(start_ip),
				decision.EndIPGTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		} else { /*decision is contained within {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPGTE(start_ip),
				decision.EndIPLTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		}
	} else if ip_sz == 16 {
		if contains { /*decision contains {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip < query.start_ip
					decision.StartIPLT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix <= query.start_suffix
						decision.StartSuffixLTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip > query.end_ip
					decision.EndIPGT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix >= query.end_suffix
						decision.EndSuffixGTE(end_sfx),
					),
				),
			))
		} else {
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip > query.start_ip
					decision.StartIPGT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix >= query.start_suffix
						decision.StartSuffixGTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip < query.end_ip
					decision.EndIPLT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix <= query.end_suffix
						decision.EndSuffixLTE(end_sfx),
					),
				),
			))
		}
	} else if ip_sz != 0 {
		return "0", errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}

	nbDeleted, err := decisions.Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteDecisionsWithFilter : %s", err)
		return "0", errors.Wrap(DeleteFail, "decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

// SoftDeleteDecisionsWithFilter updates the expiration time to now() for the decisions matching the filter
func (c *Client) SoftDeleteDecisionsWithFilter(filter map[string][]string) (string, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains bool = true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/
	decisions := c.Ent.Decision.Update().Where(decision.UntilGT(time.Now().UTC()))
	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return "0", errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scopes":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "origin":
			decisions = decisions.Where(decision.OriginEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.ValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return "0", errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		default:
			return "0", errors.Wrapf(InvalidFilter, "'%s' doesn't exist", param)
		}
	}
	if ip_sz == 4 {
		if contains {
			/*Decision contains {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPLTE(start_ip),
				decision.EndIPGTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		} else {
			/*Decision is contained within {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPGTE(start_ip),
				decision.EndIPLTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		}
	} else if ip_sz == 16 {
		/*decision contains {start_ip,end_ip}*/
		if contains {
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip < query.start_ip
					decision.StartIPLT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix <= query.start_suffix
						decision.StartSuffixLTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip > query.end_ip
					decision.EndIPGT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix >= query.end_suffix
						decision.EndSuffixGTE(end_sfx),
					),
				),
			))
		} else {
			/*decision is contained within {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip > query.start_ip
					decision.StartIPGT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix >= query.start_suffix
						decision.StartSuffixGTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip < query.end_ip
					decision.EndIPLT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix <= query.end_suffix
						decision.EndSuffixLTE(end_sfx),
					),
				),
			))
		}
	} else if ip_sz != 0 {
		return "0", errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}
	nbDeleted, err := decisions.SetUntil(time.Now().UTC()).Save(c.CTX)
	if err != nil {
		c.Log.Warningf("SoftDeleteDecisionsWithFilter : %s", err)
		return "0", errors.Wrap(DeleteFail, "soft delete decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

//SoftDeleteDecisionByID set the expiration of a decision to now()
func (c *Client) SoftDeleteDecisionByID(decisionID int) (int, error) {
	nbUpdated, err := c.Ent.Decision.Update().Where(decision.IDEQ(decisionID)).SetUntil(time.Now().UTC()).Save(c.CTX)
	if err != nil || nbUpdated == 0 {
		c.Log.Warningf("SoftDeleteDecisionByID : %v (nb soft deleted: %d)", err, nbUpdated)
		return 0, errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionID)
	}

	if nbUpdated == 0 {
		return 0, ItemNotFound
	}
	return nbUpdated, nil
}

func (c *Client) CountDecisionsByValue(decisionValue string) (int, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz, count int
	ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(decisionValue)

	if err != nil {
		return 0, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", decisionValue, err)
	}

	contains := true
	decisions := c.Ent.Decision.Query()
	decisions, err = applyStartIpEndIpFilter(decisions, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	if err != nil {
		return 0, errors.Wrapf(err, "fail to apply StartIpEndIpFilter")
	}

	count, err = decisions.Count(c.CTX)
	if err != nil {
		return 0, errors.Wrapf(err, "fail to count decisions")
	}

	return count, nil
}

func (c *Client) CountDecisionsSinceByValue(decisionValue string, since time.Time) (int, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz, count int
	ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(decisionValue)

	if err != nil {
		return 0, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", decisionValue, err)
	}

	contains := true
	decisions := c.Ent.Decision.Query().Where(
		decision.CreatedAtGT(since),
	)
	decisions, err = applyStartIpEndIpFilter(decisions, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	if err != nil {
		return 0, errors.Wrapf(err, "fail to apply StartIpEndIpFilter")
	}
	count, err = decisions.Count(c.CTX)
	if err != nil {
		return 0, errors.Wrapf(err, "fail to count decisions")
	}

	return count, nil
}

func applyStartIpEndIpFilter(decisions *ent.DecisionQuery, contains bool, ip_sz int, start_ip int64, start_sfx int64, end_ip int64, end_sfx int64) (*ent.DecisionQuery, error) {
	if ip_sz == 4 {
		if contains {
			/*Decision contains {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPLTE(start_ip),
				decision.EndIPGTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		} else {
			/*Decision is contained within {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				decision.StartIPGTE(start_ip),
				decision.EndIPLTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		}
	} else if ip_sz == 16 {
		/*decision contains {start_ip,end_ip}*/
		if contains {
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip < query.start_ip
					decision.StartIPLT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix <= query.start_suffix
						decision.StartSuffixLTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip > query.end_ip
					decision.EndIPGT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix >= query.end_suffix
						decision.EndSuffixGTE(end_sfx),
					),
				),
			))
		} else {
			/*decision is contained within {start_ip,end_ip}*/
			decisions = decisions.Where(decision.And(
				//matching addr size
				decision.IPSizeEQ(int64(ip_sz)),
				decision.Or(
					//decision.start_ip > query.start_ip
					decision.StartIPGT(start_ip),
					decision.And(
						//decision.start_ip == query.start_ip
						decision.StartIPEQ(start_ip),
						//decision.start_suffix >= query.start_suffix
						decision.StartSuffixGTE(start_sfx),
					)),
				decision.Or(
					//decision.end_ip < query.end_ip
					decision.EndIPLT(end_ip),
					decision.And(
						//decision.end_ip == query.end_ip
						decision.EndIPEQ(end_ip),
						//decision.end_suffix <= query.end_suffix
						decision.EndSuffixLTE(end_sfx),
					),
				),
			))
		}
	} else if ip_sz != 0 {
		return nil, errors.Wrapf(InvalidFilter, "unknown ip size %d", ip_sz)
	}
	return decisions, nil
}

func decisionPredicatesFromStr(s string, predicateFunc func(string) predicate.Decision) []predicate.Decision {
	words := strings.Split(s, ",")
	predicates := make([]predicate.Decision, len(words))
	for i, word := range words {
		predicates[i] = predicateFunc(word)
	}
	return predicates
}
