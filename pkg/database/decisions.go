package database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"entgo.io/ent/dialect/sql"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
)

const decisionDeleteBulkSize = 256 // scientifically proven to be the best value for bulk delete

type DecisionsByScenario struct {
	Scenario string
	Count    int
	Origin   string
	Type     string
}

func (c *Client) QueryAllDecisionsWithFilters(ctx context.Context, filter map[string][]string) ([]*ent.Decision, error) {
	// Do not select all fields.
	// This can get pretty expensive network-wise if there are a lot of decisions and you are using a remote database
	query := c.Ent.Decision.Query().
		Select(decision.FieldID, decision.FieldUntil, decision.FieldScenario, decision.FieldScope, decision.FieldValue, decision.FieldType, decision.FieldOrigin, decision.FieldUUID).
		Where(
			decision.UntilGT(time.Now().UTC()),
		)
	// Allow a bouncer to ask for non-deduplicated results
	if v, ok := filter["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := applyDecisionFilter(query, filter)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("get all decisions with filters: %w", QueryFail)
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(ctx)
	if err != nil {
		c.Log.Warningf("QueryAllDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("get all decisions with filters: %w", QueryFail)
	}

	return data, nil
}

func (c *Client) QueryExpiredDecisionsWithFilters(ctx context.Context, filter map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().
		Select(decision.FieldID, decision.FieldUntil, decision.FieldScenario, decision.FieldScope, decision.FieldValue, decision.FieldType, decision.FieldOrigin, decision.FieldUUID).
		Where(
			decision.UntilLT(time.Now().UTC()),
		)
	// Allow a bouncer to ask for non-deduplicated results
	if v, ok := filter["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := applyDecisionFilter(query, filter)

	query = query.Order(ent.Asc(decision.FieldID))

	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("get expired decisions with filters: %w", QueryFail)
	}

	data, err := query.All(ctx)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("expired decisions: %w", QueryFail)
	}

	return data, nil
}

func (c *Client) QueryDecisionCountByScenario(ctx context.Context) ([]*DecisionsByScenario, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)

	query, err := applyDecisionFilter(query, make(map[string][]string))
	if err != nil {
		c.Log.Warningf("QueryDecisionCountByScenario : %s", err)
		return nil, fmt.Errorf("count all decisions with filters: %w", QueryFail)
	}

	var r []*DecisionsByScenario

	err = query.GroupBy(decision.FieldScenario, decision.FieldOrigin, decision.FieldType).Aggregate(ent.Count()).Scan(ctx, &r)
	if err != nil {
		c.Log.Warningf("QueryDecisionCountByScenario : %s", err)
		return nil, fmt.Errorf("count all decisions with filters: %w", QueryFail)
	}

	return r, nil
}

func (c *Client) QueryDecisionWithFilter(ctx context.Context, filter map[string][]string) ([]*ent.Decision, error) {
	var (
		err  error
		data []*ent.Decision
	)

	query := c.Ent.Decision.Query().
		Where(decision.UntilGTE(time.Now().UTC()))

	query, err = applyDecisionFilter(query, filter)
	if err != nil {
		return []*ent.Decision{}, err
	}

	err = query.Select(
		decision.FieldID,
		decision.FieldUntil,
		decision.FieldScenario,
		decision.FieldType,
		decision.FieldStartIP,
		decision.FieldEndIP,
		decision.FieldValue,
		decision.FieldScope,
		decision.FieldOrigin,
	).Scan(ctx, &data)
	if err != nil {
		c.Log.Warningf("QueryDecisionWithFilter : %s", err)
		return []*ent.Decision{}, fmt.Errorf("query decision failed: %w", QueryFail)
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

func (c *Client) QueryExpiredDecisionsSinceWithFilters(ctx context.Context, since *time.Time, filter map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilLT(time.Now().UTC()),
	)

	if since != nil {
		query = query.Where(decision.UntilGT(*since))
	}

	// Allow a bouncer to ask for non-deduplicated results
	if v, ok := filter["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := applyDecisionFilter(query, filter)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("expired decisions with filters: %w", QueryFail)
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(ctx)
	if err != nil {
		c.Log.Warningf("QueryExpiredDecisionsSinceWithFilters : %s", err)
		return []*ent.Decision{}, fmt.Errorf("expired decisions with filters: %w", QueryFail)
	}

	return data, nil
}

func (c *Client) QueryNewDecisionsSinceWithFilters(ctx context.Context, since *time.Time, filter map[string][]string) ([]*ent.Decision, error) {
	query := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)

	errorMsg := "new decisions"

	if since != nil {
		query = query.Where(decision.CreatedAtGT(*since))

		errorMsg = fmt.Sprintf("%s since %q", errorMsg, since)
	}

	// Allow a bouncer to ask for non-deduplicated results
	if v, ok := filter["dedup"]; !ok || v[0] != "false" {
		query = query.Where(longestDecisionForScopeTypeValue)
	}

	query, err := applyDecisionFilter(query, filter)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)

		return nil, fmt.Errorf("%w: %s", QueryFail, errorMsg)
	}

	query = query.Order(ent.Asc(decision.FieldID))

	data, err := query.All(ctx)
	if err != nil {
		c.Log.Warningf("QueryNewDecisionsSinceWithFilters : %s", err)

		return nil, fmt.Errorf("%w: %s", QueryFail, errorMsg)
	}

	return data, nil
}

// ExpireDecisionsWithFilter updates the expiration time to now() for the decisions matching the filter, and returns the updated items
func (c *Client) ExpireDecisionsWithFilter(ctx context.Context, filter map[string][]string) (int, []*ent.Decision, error) {
	var (
		err error
		rng csnet.Range
	)

	contains := true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/
	decisions := c.Ent.Decision.Query().Where(decision.UntilGT(time.Now().UTC()))

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return 0, nil, fmt.Errorf("invalid contains value: %w: %w", err, InvalidFilter)
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
			rng, err = csnet.NewRange(value[0])
			if err != nil {
				return 0, nil, fmt.Errorf("unable to convert '%s' to int: %w: %w", value[0], err, InvalidIPOrRange)
			}
		case "scenario":
			decisions = decisions.Where(decision.ScenarioEQ(value[0]))
		default:
			return 0, nil, fmt.Errorf("'%s' doesn't exist: %w", param, InvalidFilter)
		}
	}

	decisions, err = decisionIPFilter(decisions, contains, rng)
	if err != nil {
		return 0, nil, err
	}

	decisionsToDelete, err := decisions.All(ctx)
	if err != nil {
		c.Log.Warningf("ExpireDecisionsWithFilter : %s", err)
		return 0, nil, fmt.Errorf("expire decisions with provided filter: %w", DeleteFail)
	}

	count, err := c.ExpireDecisions(ctx, decisionsToDelete)
	if err != nil {
		return 0, nil, fmt.Errorf("expire decisions with provided filter: %w: %w", err, DeleteFail)
	}

	return count, decisionsToDelete, err
}

func decisionIDs(decisions []*ent.Decision) []int {
	ids := make([]int, len(decisions))
	for i, d := range decisions {
		ids[i] = d.ID
	}

	return ids
}

// expireDecisionBatch expires the decisions as a single operation.
func (c *Client) expireDecisionBatch(ctx context.Context, batch []*ent.Decision, now time.Time) (int, error) {
	ids := decisionIDs(batch)

	rows, err := c.Ent.Decision.
		Update().
		Where(decision.IDIn(ids...)).
		SetUntil(now).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("expire decisions with provided filter: %w", err)
	}

	return rows, nil
}

// ExpireDecisions sets the expiration of a list of decisions to now(),
// in multiple operations if len(decisions) > decisionDeleteBulkSize.
// It returns the number of impacted decisions for the CAPI/PAPI, even in case of error.
func (c *Client) ExpireDecisions(ctx context.Context, decisions []*ent.Decision) (int, error) {
	if len(decisions) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()

	total := 0
	err := slicetools.Batch(ctx, decisions, decisionDeleteBulkSize, func(ctx context.Context, batch []*ent.Decision) error {
		rows, err := c.expireDecisionBatch(ctx, batch, now)
		if err != nil {
			return err
		}
		total += rows
		return nil
	})

	return total, err
}

// deleteDecisionBatch removes the decisions as a single operation.
func (c *Client) deleteDecisionBatch(ctx context.Context, batch []*ent.Decision) (int, error) {
	ids := decisionIDs(batch)

	rows, err := c.Ent.Decision.
		Delete().
		Where(decision.IDIn(ids...)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("hard delete decisions with provided filter: %w", err)
	}

	return rows, nil
}

// DeleteDecisions removes a list of decisions from the database,
// in multiple operations if len(decisions) > decisionDeleteBulkSize.
// It returns the number of impacted decisions for the CAPI/PAPI, even in case of error.
func (c *Client) DeleteDecisions(ctx context.Context, decisions []*ent.Decision) (int, error) {
	if len(decisions) == 0 {
		return 0, nil
	}

	total := 0
	err := slicetools.Batch(ctx, decisions, decisionDeleteBulkSize, func(ctx context.Context, batch []*ent.Decision) error {
		rows, err := c.deleteDecisionBatch(ctx, batch)
		if err != nil {
			return err
		}
		total += rows
		return nil
	})

	return total, err
}

// ExpireDecisionByID set the expiration of a decision to now()
func (c *Client) ExpireDecisionByID(ctx context.Context, decisionID int) (int, []*ent.Decision, error) {
	toUpdate, err := c.Ent.Decision.Query().Where(decision.IDEQ(decisionID)).All(ctx)

	// XXX: do we want 500 or 404 here?
	if err != nil || len(toUpdate) == 0 {
		c.Log.Warningf("ExpireDecisionByID : %v (nb expired: %d)", err, len(toUpdate))
		return 0, nil, fmt.Errorf("decision with id '%d' doesn't exist: %w", decisionID, DeleteFail)
	}

	if len(toUpdate) == 0 {
		return 0, nil, ItemNotFound
	}

	count, err := c.ExpireDecisions(ctx, toUpdate)

	return count, toUpdate, err
}

func (c *Client) CountDecisionsByValue(ctx context.Context, value string, since *time.Time, onlyActive bool) (int, error) {
	rng, err := csnet.NewRange(value)
	if err != nil {
		return 0, fmt.Errorf("unable to convert '%s' to int: %w", value, err)
	}

	contains := true
	decisions := c.Ent.Decision.Query()

	decisions, err = decisionIPFilter(decisions, contains, rng)
	if err != nil {
		return 0, fmt.Errorf("fail to apply StartIpEndIpFilter: %w", err)
	}

	if since != nil {
		decisions = decisions.Where(decision.CreatedAtGT(*since))
	}

	if onlyActive {
		decisions = decisions.Where(decision.UntilGT(time.Now().UTC()))
	}

	count, err := decisions.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("fail to count decisions: %w", err)
	}

	return count, nil
}

func (c *Client) GetActiveDecisionsTimeLeftByValue(ctx context.Context, decisionValue string) (time.Duration, error) {
	rng, err := csnet.NewRange(decisionValue)
	if err != nil {
		return 0, fmt.Errorf("unable to convert '%s' to int: %w", decisionValue, err)
	}

	contains := true
	decisions := c.Ent.Decision.Query().Where(
		decision.UntilGT(time.Now().UTC()),
	)

	decisions, err = decisionIPFilter(decisions, contains, rng)
	if err != nil {
		return 0, fmt.Errorf("fail to apply StartIpEndIpFilter: %w", err)
	}

	decisions = decisions.Order(ent.Desc(decision.FieldUntil))

	decision, err := decisions.First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return 0, fmt.Errorf("fail to get decision: %w", err)
	}

	if decision == nil {
		return 0, nil
	}

	return decision.Until.Sub(time.Now().UTC()), nil
}
