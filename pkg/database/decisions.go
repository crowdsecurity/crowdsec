package database

import (
	"fmt"
	"strings"
	"time"

	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
)

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {

	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var ip_sz int
	var contains bool = true
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
		case "scope":
			for i, scope := range value {
				switch strings.ToLower(scope) {
				case "ip":
					value[i] = types.Ip
				case "range":
					value[i] = types.Range
				case "country":
					value[i] = types.Country
				case "as":
					value[i] = types.AS
				}
			}
			query = query.Where(decision.ScopeIn(value...))
		case "value":
			query = query.Where(decision.ValueEQ(value[0]))
		case "type":
			query = query.Where(decision.TypeEQ(value[0]))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		default:
			return query, errors.Wrapf(InvalidFilter, "'%s' doesn't exist", param)
		}
	}

	if ip_sz == 4 {

		if contains { /*decision contains {start_ip,end_ip}*/
			query = query.Where(decision.And(
				decision.StartIPLTE(start_ip),
				decision.EndIPGTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		} else { /*decision is contained within {start_ip,end_ip}*/
			query = query.Where(decision.And(
				decision.StartIPGTE(start_ip),
				decision.EndIPLTE(end_ip),
				decision.IPSizeEQ(int64(ip_sz)),
			))
		}
	} else if ip_sz == 16 {

		if contains { /*decision contains {start_ip,end_ip}*/
			query = query.Where(decision.And(
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
		} else { /*decision is contained {start_ip,end_ip}*/
			query = query.Where(decision.And(
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
		return nil, errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}
	return query, nil
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

func (c *Client) QueryAllDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(decision.UntilGT(time.Now().UTC()))
	query, err := BuildDecisionRequestWithFilter(query, filters)

	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}

	data, err := query.All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions with filters")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisionsWithFilters(filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(decision.UntilLT(time.Now().UTC()))
	query, err := BuildDecisionRequestWithFilter(query, filters)

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

func (c *Client) QueryExpiredDecisionsSinceWithFilters(since time.Time, filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(decision.UntilLT(time.Now().UTC())).Where(decision.UntilGT(since))
	query, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	data, err := query.All(c.CTX)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions with filters")
	}

	return data, nil
}

func (c *Client) QueryNewDecisionsSinceWithFilters(since time.Time, filters map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(decision.CreatedAtGT(since)).Where(decision.UntilGT(time.Now().UTC()))
	query, err := BuildDecisionRequestWithFilter(query, filters)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, errors.Wrapf(QueryFail, "new decisions since '%s'", since.String())
	}
	data, err := query.All(c.CTX)
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

// SoftDeleteDecisionsWithFilter udpate the expiration time to now() for the decisions matching the filter
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
func (c *Client) SoftDeleteDecisionByID(decisionID int) error {
	nbUpdated, err := c.Ent.Decision.Update().Where(decision.IDEQ(decisionID)).SetUntil(time.Now().UTC()).Save(c.CTX)
	if err != nil || nbUpdated == 0 {
		c.Log.Warningf("SoftDeleteDecisionByID : %v (nb soft deleted: %d)", err, nbUpdated)
		return errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionID)
	}

	if nbUpdated == 0 {
		return ItemNotFound
	}
	return nil
}
