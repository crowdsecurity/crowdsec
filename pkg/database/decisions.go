package database

import (
	"fmt"
	"time"

	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/pkg/errors"
)

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	var err error
	var startIP, endIP int64
	for param, value := range filter {
		switch param {
		case "scope":
			query = query.Where(decision.ScopeEQ(value[0]))
		case "value":
			query = query.Where(decision.ValueEQ(value[0]))
		case "type":
			query = query.Where(decision.TypeEQ(value[0]))
		case "ip":
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				return nil, errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to parse '%s': %s", value[0], err))
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				return nil, errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to convert '%s' to int interval: %s", value[0], err))
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
			if err != nil {
				return nil, errors.Wrap(InvalidIPOrRange, fmt.Sprintf("unable to convert '%s' to int interval: %s", value[0], err))
			}
		default:
			return query, errors.Wrap(InvalidFilter, fmt.Sprintf("'%s' doesn't exist", param))
		}
	}

	if startIP != 0 && endIP != 0 {
		query = query.Where(decision.And(
			decision.StartIPGTE(startIP),
			decision.EndIPLTE(endIP),
		))
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
		return []*ent.Decision{}, errors.Wrap(QueryFail, "creating decision failed")
	}

	return data, nil
}

func (c *Client) QueryAllDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.UntilLT(time.Now())).All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}
	return data, nil
}

func (c *Client) QueryNewDecisionsSince(since time.Time) ([]*ent.Decision, error) {
	data, err := c.Ent.Decision.Query().Where(decision.CreatedAtGT(since)).All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, fmt.Sprintf("new decisions since '%s'", since.String()))
	}

	return data, nil
}

func (c *Client) DeleteDecisionById(decisionId int) error {
	err := c.Ent.Decision.DeleteOneID(decisionId).Exec(c.CTX)
	if err != nil {
		return errors.Wrap(DeleteFail, fmt.Sprintf("decision with id '%d' doesn't exist", decisionId))
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
			decisions = decisions.Where(decision.And(
				decision.StartIPGTE(startIP),
				decision.EndIPLTE(endIP),
			))
		}
	}

	nbDeleted, err := decisions.Exec(c.CTX)
	if err != nil {
		return "0", errors.Wrap(DeleteFail, "decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

func (c *Client) SoftDeleteDecisionsWithFilter(filter map[string][]string) (string, error) {
	var err error
	var startIP, endIP int64

	decisions := c.Ent.Decision.Update()

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
			decisions = decisions.Where(decision.And(
				decision.StartIPGTE(startIP),
				decision.EndIPLTE(endIP),
			))
		}
	}
	nbDeleted, err := decisions.SetUntil(time.Now()).Save(c.CTX)
	if err != nil {
		return "0", errors.Wrap(DeleteFail, "soft delete decisions with provided filter")
	}
	return strconv.Itoa(nbDeleted), nil
}

func (c *Client) SoftDeleteAllDecisions() (string, error) {
	nbDeleted, err := c.Ent.Decision.Update().SetUntil(time.Now()).Save(c.CTX)
	if err != nil {
		return "0", errors.Wrap(DeleteFail, "soft delete all decisions")
	}
	return strconv.Itoa(nbDeleted), nil

}

func (c *Client) SoftDeleteDecisionById(decisionId int) error {
	_, err := c.Ent.Decision.Update().Where(decision.IDEQ(decisionId)).SetUntil(time.Now()).Save(c.CTX)
	if err != nil {
		return errors.Wrap(DeleteFail, fmt.Sprintf("decision with id '%d' doesn't exist", decisionId))
	}
	return nil
}
