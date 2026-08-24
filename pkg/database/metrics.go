package database

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
)

func (c *Client) CreateMetric(ctx context.Context, generatedType metric.GeneratedType, generatedBy string, receivedAt time.Time, payload string) (*ent.Metric, error) {
	metric, err := c.Ent.Metric.
		Create().
		SetGeneratedType(generatedType).
		SetGeneratedBy(generatedBy).
		SetReceivedAt(receivedAt).
		SetPayload(payload).
		Save(ctx)
	if err != nil {
		c.Log.Warningf("CreateMetric: %s", err)
		return nil, fmt.Errorf("storing metrics snapshot for '%s' at %s: %w", generatedBy, receivedAt, InsertFail)
	}

	return metric, nil
}

func (c *Client) GetLPUsageMetricsByMachineID(ctx context.Context, machineId string, toSend bool) ([]*ent.Metric, error) {
	query := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeLP),
			metric.GeneratedByEQ(machineId),
		)

	if toSend {
		query = query.Where(metric.PushedAtIsNil())
	}

	metrics, err := query.All(ctx)
	if err != nil {
		c.Log.Warningf("GetLPUsageMetricsByOrigin: %s", err)
		return nil, fmt.Errorf("getting LP usage metrics by origin %s: %w", machineId, err)
	}

	return metrics, nil
}

func (c *Client) GetBouncerUsageMetricsByName(ctx context.Context, bouncerName string) ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeRC),
			metric.GeneratedByEQ(bouncerName),
			metric.PushedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		c.Log.Warningf("GetBouncerUsageMetricsByName: %s", err)
		return nil, fmt.Errorf("getting bouncer usage metrics by name %s: %w", bouncerName, err)
	}

	return metrics, nil
}

func (c *Client) MarkUsageMetricsAsSent(ctx context.Context, ids []int) error {
	_, err := c.Ent.Metric.Update().
		Where(metric.IDIn(ids...)).
		SetPushedAt(time.Now().UTC()).
		Save(ctx)
	if err != nil {
		c.Log.Warningf("MarkUsageMetricsAsSent: %s", err)
		return fmt.Errorf("marking usage metrics as sent: %w", err)
	}

	return nil
}

// GetUnsentMetrics returns metrics not pushed to CAPI yet, across all sources, ordered by id.
// Callers walk the backlog by passing back the id of the last row they consumed.
func (c *Client) GetUnsentMetrics(ctx context.Context, afterID int, limit int) ([]*ent.Metric, error) {
	metrics, err := c.Ent.Metric.Query().
		Where(
			metric.PushedAtIsNil(),
			metric.IDGT(afterID),
		).
		Order(ent.Asc(metric.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		c.Log.Warningf("GetUnsentMetrics: %s", err)
		return nil, fmt.Errorf("getting unsent usage metrics: %w", err)
	}

	return metrics, nil
}

// MarkStaleUsageMetricsAsSent gives up on metrics too old to be worth pushing, so a CAPI outage
// cannot leave a growing backlog behind. The rows live on until the age flush, for cscli.
func (c *Client) MarkStaleUsageMetricsAsSent(ctx context.Context, before time.Time) (int, error) {
	updated, err := c.Ent.Metric.Update().
		Where(
			metric.PushedAtIsNil(),
			metric.ReceivedAtLT(before),
		).
		SetPushedAt(time.Now().UTC()).
		Save(ctx)
	if err != nil {
		c.Log.Warningf("MarkStaleUsageMetricsAsSent: %s", err)
		return 0, fmt.Errorf("marking stale usage metrics as sent: %w", err)
	}

	return updated, nil
}
