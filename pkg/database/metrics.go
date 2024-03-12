package database

import (
	"time"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
)

// TODO:
// what if they are alrady in the db (should get an error from the unique index)
// CollectMetricsToPush (count limit? including stale?)
// SetPushedMetrics
// RemoveOldMetrics
// avoid errors.Wrapf


func (c *Client) CreateMetric(generatedType metric.GeneratedType, generatedBy string, collectedAt time.Time, payload string) (*ent.Metric, error) {
	metric, err := c.Ent.Metric.
		Create().
		SetGeneratedType(generatedType).
		SetGeneratedBy(generatedBy).
		SetCollectedAt(collectedAt).
		SetPayload(payload).
		Save(c.CTX)

	if err != nil {
		c.Log.Warningf("CreateMetric: %s", err)
		return nil, errors.Wrapf(InsertFail, "creating metrics set for '%s' at %s", generatedBy, collectedAt)
	}

	return metric, nil
}
