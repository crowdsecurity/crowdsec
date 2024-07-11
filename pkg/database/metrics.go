package database

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
)

// TODO:
// what if they are alrady in the db (should get an error from the unique index)
// CollectMetricsToPush (count limit? including stale?)
// SetPushedMetrics
// RemoveOldMetrics

func (c *Client) CreateMetric(generatedType metric.GeneratedType, generatedBy string, collectedAt time.Time, payload string) (*ent.Metric, error) {
	metric, err := c.Ent.Metric.
		Create().
		SetGeneratedType(generatedType).
		SetGeneratedBy(generatedBy).
		SetCollectedAt(collectedAt).
		SetPayload(payload).
		Save(c.CTX)

	switch {
	case ent.IsConstraintError(err):
		// pretty safe guess, it's the unique index
		c.Log.Infof("storing metrics snapshot for '%s' at %s: already exists", generatedBy, collectedAt)
		// it's polite to accept a duplicate snapshot without any error
		return nil, nil
	case err != nil:
		c.Log.Warningf("CreateMetric: %s", err)
		return nil, fmt.Errorf("storing metrics snapshot for '%s' at %s: %w", generatedBy, collectedAt, InsertFail)
	}

	return metric, nil
}

func (c *Client) GetLPsUsageMetrics() ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeLP),
			metric.PushedAtIsNil(),
		).
		Order(ent.Desc(metric.FieldCollectedAt)).
		All(c.CTX)
	if err != nil {
		c.Log.Warningf("GetLPsUsageMetrics: %s", err)
		return nil, fmt.Errorf("getting LPs usage metrics: %w", err)
	}

	return metrics, nil
}

func (c *Client) GetLPUsageMetricsByMachineID(machineId string) ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeLP),
			metric.GeneratedByEQ(machineId),
			metric.PushedAtIsNil(),
		).
		Order(ent.Desc(metric.FieldCollectedAt)).
		All(c.CTX)
	if err != nil {
		c.Log.Warningf("GetLPUsageMetricsByOrigin: %s", err)
		return nil, fmt.Errorf("getting LP usage metrics by origin %s: %w", machineId, err)
	}

	return metrics, nil
}

func (c *Client) GetBouncersUsageMetrics() ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeRC),
			metric.PushedAtIsNil(),
		).
		Order(ent.Desc(metric.FieldCollectedAt)).
		All(c.CTX)
	if err != nil {
		c.Log.Warningf("GetBouncersUsageMetrics: %s", err)
		return nil, fmt.Errorf("getting bouncers usage metrics: %w", err)
	}

	return metrics, nil
}

func (c *Client) GetBouncerUsageMetricsByName(bouncerName string) ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeRC),
			metric.GeneratedByEQ(bouncerName),
			metric.PushedAtIsNil(),
		).
		Order(ent.Desc(metric.FieldCollectedAt)).
		All(c.CTX)
	if err != nil {
		c.Log.Warningf("GetBouncerUsageMetricsByName: %s", err)
		return nil, fmt.Errorf("getting bouncer usage metrics by name %s: %w", bouncerName, err)
	}

	return metrics, nil
}

func (c *Client) MarkUsageMetricsAsSent(ids []int) error {
	_, err := c.Ent.Metric.Update().
		Where(metric.IDIn(ids...)).
		// XXX: no utc?
		SetPushedAt(time.Now()).
		Save(c.CTX)
	if err != nil {
		c.Log.Warningf("MarkUsageMetricsAsSent: %s", err)
		return fmt.Errorf("marking usage metrics as sent: %w", err)
	}

	return nil
}
