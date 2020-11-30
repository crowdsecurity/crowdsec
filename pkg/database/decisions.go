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
	log "github.com/sirupsen/logrus"
)

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	var err error
	var startIP, endIP int64

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
		case "scope":
			var scope string = value[0]
			if strings.ToLower(scope) == "ip" {
				scope = types.Ip
			} else if strings.ToLower(scope) == "range" {
				scope = types.Range
			}
			query = query.Where(decision.ScopeEQ(scope))
		case "value":
			query = query.Where(decision.ValueEQ(value[0]))
		case "type":
			query = query.Where(decision.TypeEQ(value[0]))
		case "ip":
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to parse '%s': %s", value[0], err)
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
			}
		default:
			return query, errors.Wrapf(InvalidFilter, "'%s' doesn't exist", param)
		}
	}

	if startIP != 0 && endIP != 0 {
		/*the user is checking for a single IP*/
		if startIP == endIP {
			//DECISION_START <= IP_Q >= DECISON_END
			query = query.Where(decision.And(
				decision.StartIPLTE(startIP),
				decision.EndIPGTE(endIP),
			))
		} else { /*the user is checking for a RANGE */
			//START_Q >= DECISION_START AND END_Q <= DECISION_END
			query = query.Where(decision.And(
				decision.StartIPGTE(startIP),
				decision.EndIPLTE(endIP),
			))
		}
	}
	return query, nil
}

func (c *Client) QueryDecisionWithFilter(filter map[string][]string) ([]*ent.Decision, error) {
	var data []*ent.Decision
	var err error

	decisions := c.Ent.Decision.Query().
		Where(decision.UntilGTE(time.Now()))

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
		log.Warningf("QueryDecisionWithFilter : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "query decision failed")
	}

	return data, nil
}

func (c *Client) QueryAllDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.UntilGT(time.Now())).All(c.CTX)
	if err != nil {
		log.Warningf("QueryAllDecisions : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.UntilLT(time.Now())).All(c.CTX)
	if err != nil {
		log.Warningf("QueryExpiredDecisions : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisionsSince(since time.Time) ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.UntilLT(time.Now())).Where(decision.UntilGT(since)).All(c.CTX)
	if err != nil {
		log.Warningf("QueryExpiredDecisionsSince : %s", err)
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}
	return data, nil
}

func (c *Client) QueryNewDecisionsSince(since time.Time) ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.CreatedAtGT(since)).All(c.CTX)
	if err != nil {
		log.Warningf("QueryNewDecisionsSince : %s", err)
		return []*ent.Decision{}, errors.Wrapf(QueryFail, "new decisions since '%s'", since.String())
	}
	return data, nil
}

func (c *Client) DeleteDecisionById(decisionId int) error {
	err := c.Ent.Decision.DeleteOneID(decisionId).Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteDecisionById : %s", err)
		return errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionId)
	}
	return nil
}

func (c *Client) DeleteDecisionsWithFilter(filter map[string][]string) (string, error) {
	var err error
	var startIP, endIP int64

	decisions := c.Ent.Decision.Delete()

	for param, value := range filter {
		switch param {
		case "scope":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.ValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		case "ip":
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				return "0", errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to parse '%s': %s", value[0], err))
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				return "0", errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to convert '%s' to int interval: %s", value[0], err))
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
			if err != nil {
				return "0", errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to convert '%s' to int interval: %s", value[0], err))
			}
		default:
			return "0", errors.Wrap(InvalidFilter, fmt.Sprintf("'%s' doesn't exist", param))
		}

		if startIP != 0 && endIP != 0 {
			/*the user is checking for a single IP*/
			if startIP == endIP {
				//DECISION_START <= IP_Q >= DECISON_END
				decisions = decisions.Where(decision.And(
					decision.StartIPLTE(startIP),
					decision.EndIPGTE(endIP),
				))
			} else { /*the user is checking for a RANGE */
				//START_Q >= DECISION_START AND END_Q <= DECISION_END
				decisions = decisions.Where(decision.And(
					decision.StartIPGTE(startIP),
					decision.EndIPLTE(endIP),
				))
			}
		}
	}

	nbDeleted, err := decisions.Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteDecisionsWithFilter : %s", err)
		return "0", errors.Wrap(DeleteFail, "decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

// SoftDeleteDecisionsWithFilter udpate the expiration time to now() for the decisions matching the filter
func (c *Client) SoftDeleteDecisionsWithFilter(filter map[string][]string) (string, error) {
	var err error
	var startIP, endIP int64

	decisions := c.Ent.Decision.Update().Where(decision.UntilGT(time.Now()))
	for param, value := range filter {
		switch param {
		case "scope":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.ValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		case "ip":
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				return "0", errors.Wrapf(InvalidIPOrRange, "unable to parse '%s': %s", value[0], err)
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				return "0", errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
			if err != nil {
				return "0", errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
			}
		default:
			return "0", errors.Wrapf(InvalidFilter, "'%s' doesn't exist", param)
		}

		if startIP != 0 && endIP != 0 {
			/*the user is checking for a single IP*/
			if startIP == endIP {
				//DECISION_START <= IP_Q >= DECISON_END
				decisions = decisions.Where(decision.And(
					decision.StartIPLTE(startIP),
					decision.EndIPGTE(endIP),
				))
			} else { /*the user is checking for a RANGE */
				//START_Q >= DECISION_START AND END_Q <= DECISION_END
				decisions = decisions.Where(decision.And(
					decision.StartIPGTE(startIP),
					decision.EndIPLTE(endIP),
				))
			}
		}
	}
	nbDeleted, err := decisions.SetUntil(time.Now()).Save(c.CTX)
	if err != nil {
		log.Warningf("SoftDeleteDecisionsWithFilter : %s", err)
		return "0", errors.Wrap(DeleteFail, "soft delete decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

//SoftDeleteDecisionByID set the expiration of a decision to now()
func (c *Client) SoftDeleteDecisionByID(decisionID int) error {
	nbUpdated, err := c.Ent.Decision.Update().Where(decision.IDEQ(decisionID)).SetUntil(time.Now()).Save(c.CTX)
	if err != nil || nbUpdated == 0 {
		log.Warningf("SoftDeleteDecisionByID : %v (nb soft deleted: %d)", err, nbUpdated)
		return errors.Wrapf(DeleteFail, "decision with id '%d' doesn't exist", decisionID)
	}

	if nbUpdated == 0 {
		return ItemNotFound
	}
	return nil
}
