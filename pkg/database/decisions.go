package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/pkg/errors"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DecisionsByScenario struct {
	Scenario string
	Count    int
	Origin   string
	Type     string
}

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains = true
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
	query, err = applyStartIpEndIpFilter(query, contains, ip_sz, start_ip, start_sfx, end_ip, end_sfx)
	if err != nil {
		return nil, fmt.Errorf("fail to apply StartIpEndIpFilter: %w", err)
	}
	return query, nil
}
func (c *Client) QueryAllDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)
	//Allow a bouncer to ask for non-deduplicated results
	if v, ok := filters["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := BuildDecisionRequestWithFilter(query, filters)

	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilLT(time.Now().UTC()),
	)
	//Allow a bouncer to ask for non-deduplicated results
	if v, ok := filters["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := BuildDecisionRequestWithFilter(query, filters)

	query = query.Order(ent.Asc(decision.FieldID))

	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get expired decisions with filters")
	}
	data, err := query.All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}
	return data, nil
}

func (c *Client) QueryDecisionCountByScenario(filters map[string][]string) ([]*DecisionsByScenario, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)
	query, err := BuildDecisionRequestWithFilter(query, filters)

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

func (c *Client) QueryDecisionWithFilter(filter map[string][]string) ([]*ent.Decision, error) {
	var data []*ent.Decision
	var err error

	decisions := c.Ent.Decision.Query().
		Where(decision.UntilGTE(time.Now().UTC()))

	decisions, err = BuildDecisionRequestWithFilter(decisions, filter)
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

// ent translation of https://stackoverflow.com/a/28090544
func longestDecisionForScopeTypeValue(s *sql.Selector) {
	t := sql.Table(decision.Table)
	s.LeftJoin(t).OnP(sql.And(
		sql.ColumnsEQ(
			t.C(decision.FieldValue),
			s.C(decision.FieldValue),
		),
		sql.ColumnsEQ(
			t.C(decision.FieldType),
			s.C(decision.FieldType),
		),
		sql.ColumnsEQ(
			t.C(decision.FieldScope),
			s.C(decision.FieldScope),
		),
		sql.ColumnsGT(
			t.C(decision.FieldUntil),
			s.C(decision.FieldUntil),
		),
	))
	s.Where(
		sql.IsNull(
			t.C(decision.FieldUntil),
		),
	)
}

func (c *Client) QueryExpiredDecisionsSinceWithFilters(since time.Time, filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilLT(time.Now().UTC()),
		decision.UntilGT(since),
	)
	//Allow a bouncer to ask for non-deduplicated results
	if v, ok := filters["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}
	query, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(c.CTX)
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
	//Allow a bouncer to ask for non-deduplicated results
	if v, ok := filters["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}
	query, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrapf(QueryFail, "new decisions since '%s'", since.String())
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrapf(QueryFail, "new decisions since '%s'", since.String())
	}
	return data, nil
}

func (c *Client) DeleteDecisionById(decisionId int) ([]*ent.Decision, error) {
	toDelete, err := c.Ent.Decision.Query().Where(decision.IDEQ(decisionId)).All(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteDecisionById : %s", err)
		return nil, errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionId)
	}
	count, err := c.BulkDeleteDecisions(toDelete, false)
	c.Log.Debugf("deleted %d decisions", count)
	return toDelete, err
}

func (c *Client) DeleteDecisionsWithFilter(filter map[string][]string) (string, []*ent.Decision, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains = true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer) */

	decisions := c.Ent.Decision.Query()
	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return "0", nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
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
				return "0", nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		case "scenario":
			decisions = decisions.Where(decision.ScenarioEQ(value[0]))
		default:
			return "0", nil, errors.Wrap(InvalidFilter, fmt.Sprintf("'%s' doesn't exist", param))
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
		return "0", nil, errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}

	toDelete, err := decisions.All(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteDecisionsWithFilter : %s", err)
		return "0", nil, errors.Wrap(DeleteFail, "decisions with provided filter")
	}
	count, err := c.BulkDeleteDecisions(toDelete, false)
	if err != nil {
		c.Log.Warningf("While deleting decisions : %s", err)
		return "0", nil, errors.Wrap(DeleteFail, "decisions with provided filter")
	}
	return strconv.Itoa(count), toDelete, nil
}

// SoftDeleteDecisionsWithFilter updates the expiration time to now() for the decisions matching the filter, and returns the updated items
func (c *Client) SoftDeleteDecisionsWithFilter(filter map[string][]string) (string, []*ent.Decision, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains = true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/
	decisions := c.Ent.Decision.Query().Where(decision.UntilGT(time.Now().UTC()))
	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return "0", nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scopes":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "uuid":
			decisions = decisions.Where(decision.UUIDIn(value...))
		case "origin":
			decisions = decisions.Where(decision.OriginEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.ValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return "0", nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		case "scenario":
			decisions = decisions.Where(decision.ScenarioEQ(value[0]))
		default:
			return "0", nil, errors.Wrapf(InvalidFilter, "'%s' doesn't exist", param)
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
		return "0", nil, errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}
	DecisionsToDelete, err := decisions.All(c.CTX)
	if err != nil {
		c.Log.Warningf("SoftDeleteDecisionsWithFilter : %s", err)
		return "0", nil, errors.Wrap(DeleteFail, "soft delete decisions with provided filter")
	}

	count, err := c.BulkDeleteDecisions(DecisionsToDelete, true)
	if err != nil {
		return "0", nil, errors.Wrapf(DeleteFail, "soft delete decisions with provided filter : %s", err)
	}
	return strconv.Itoa(count), DecisionsToDelete, err
}

// BulkDeleteDecisions set the expiration of a bulk of decisions to now() or hard deletes them.
// We are doing it this way so we can return impacted decisions for sync with CAPI/PAPI
func (c *Client) BulkDeleteDecisions(decisionsToDelete []*ent.Decision, softDelete bool) (int, error) {
	const bulkSize = 256 //scientifically proven to be the best value for bulk delete

	var (
		nbUpdates    int
		err          error
		totalUpdates = 0
	)

	idsToDelete := make([]int, len(decisionsToDelete))
	for i, decision := range decisionsToDelete {
		idsToDelete[i] = decision.ID
	}

	for _, chunk := range slicetools.Chunks(idsToDelete, bulkSize) {
		if softDelete {
			nbUpdates, err = c.Ent.Decision.Update().Where(
				decision.IDIn(chunk...),
			).SetUntil(time.Now().UTC()).Save(c.CTX)
			if err != nil {
				return totalUpdates, fmt.Errorf("soft delete decisions with provided filter: %w", err)
			}
		} else {
			nbUpdates, err = c.Ent.Decision.Delete().Where(
				decision.IDIn(chunk...),
			).Exec(c.CTX)
			if err != nil {
				return totalUpdates, fmt.Errorf("hard delete decisions with provided filter: %w", err)
			}
		}
		totalUpdates += nbUpdates
	}

	return totalUpdates, nil
}

// SoftDeleteDecisionByID set the expiration of a decision to now()
func (c *Client) SoftDeleteDecisionByID(decisionID int) (int, []*ent.Decision, error) {
	toUpdate, err := c.Ent.Decision.Query().Where(decision.IDEQ(decisionID)).All(c.CTX)

	// XXX: do we want 500 or 404 here?
	if err != nil || len(toUpdate) == 0 {
		c.Log.Warningf("SoftDeleteDecisionByID : %v (nb soft deleted: %d)", err, len(toUpdate))
		return 0, nil, errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionID)
	}

	if len(toUpdate) == 0 {
		return 0, nil, ItemNotFound
	}

	count, err := c.BulkDeleteDecisions(toUpdate, true)
	return count, toUpdate, err
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
	ip_sz, start_ip, start_sfx, end_ip, end_sfx, err := types.Addr2Ints(decisionValue)

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

	count, err := decisions.Count(c.CTX)
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
		return decisions, nil
	}

	if ip_sz == 16 {
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
		return decisions, nil
	}

	if ip_sz != 0 {
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
