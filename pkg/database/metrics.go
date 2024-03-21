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
// avoid errors.Wrapf


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
