package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// updateBaseMetrics updates the base metrics for a machine or bouncer
func (c *Controller) updateBaseMetrics(machineID string, bouncer *ent.Bouncer, baseMetrics models.BaseMetrics, hubItems models.HubItems, datasources map[string]int64) error {
	switch {
	case machineID != "":
		c.DBClient.MachineUpdateBaseMetrics(machineID, baseMetrics, hubItems, datasources)
	case bouncer != nil:
		c.DBClient.BouncerUpdateBaseMetrics(bouncer.Name, bouncer.Type, baseMetrics)
	default:
		return fmt.Errorf("no machineID or bouncerName set")
	}

	return nil
}

// UsageMetrics receives metrics from log processors and remediation components
func (c *Controller) UsageMetrics(gctx *gin.Context) {
	var input models.AllMetrics

	// parse the payload

	if err := gctx.ShouldBindJSON(&input); err != nil {
		log.Errorf("Failed to bind json: %s", err)
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if err := input.Validate(strfmt.Default); err != nil {
		// work around a nuisance in the generated code
		cleanErr := RepeatedPrefixError{
			OriginalError: err,
			Prefix: "validation failure list:\n",
		}
		log.Errorf("Failed to validate usage metrics: %s", cleanErr)
		gctx.JSON(http.StatusUnprocessableEntity, gin.H{"message": cleanErr.Error()})
		return
	}

	// TODO: validate payload with the right type, depending on auth context

	var (
		generatedType metric.GeneratedType
		generatedBy   string
		collectedAt   time.Time
	)

	bouncer, _ := getBouncerFromContext(gctx)
	if bouncer != nil {
		log.Tracef("Received usage metris for bouncer: %s", bouncer.Name)
		generatedType = metric.GeneratedTypeRC
		generatedBy = bouncer.Name
	}

	machineID, _ := getMachineIDFromContext(gctx)
	if machineID != "" {
		log.Tracef("Received usage metrics for log processor: %s", machineID)
		generatedType = metric.GeneratedTypeLP
		generatedBy = machineID
	}

	// TODO: if both or none are set, which error should we return?

	var (
		payload     map[string]any
		baseMetrics models.BaseMetrics
		hubItems    models.HubItems
		datasources map[string]int64
	)

	switch len(input.LogProcessors) {
	case 0:
		break
	case 1:
		// the final slice can't have more than one item,
		// guaranteed by the swagger schema
		item0 := input.LogProcessors[0]
		payload = map[string]any{
			"metrics": item0.Metrics,
		}
		baseMetrics = item0.BaseMetrics
		hubItems = item0.HubItems
		datasources = item0.Datasources
	default:
		log.Errorf("Payload has more than one log processor")
		// this is not checked in the swagger schema
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "Payload has more than one log processor"})
		return
	}

	switch len(input.RemediationComponents) {
	case 0:
		break
	case 1:
		item0 := input.RemediationComponents[0]
		payload = map[string]any{
			"type":    item0.Type,
			"metrics": item0.Metrics,
		}
		baseMetrics = item0.BaseMetrics
	default:
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "Payload has more than one remediation component"})
		return
	}

	err := c.updateBaseMetrics(machineID, bouncer, baseMetrics, hubItems, datasources)
	if err != nil {
		log.Errorf("Failed to update base metrics: %s", err)
		c.HandleDBErrors(gctx, err)
		return
	}

	if baseMetrics.Metrics != nil && len(baseMetrics.Metrics) > 0 {
		collectedAt = time.Unix(*baseMetrics.Metrics[0].Meta.UtcNowTimestamp, 0).UTC()
	} else {
		// if there's no timestamp, use the current time
		collectedAt = time.Now().UTC()
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("Failed to marshal usage metrics: %s", err)
		c.HandleDBErrors(gctx, err)
		return
	}

	if _, err := c.DBClient.CreateMetric(generatedType, generatedBy, collectedAt, string(jsonPayload)); err != nil {
		log.Error(err)
		c.HandleDBErrors(gctx, err)
		return
	}

	// if CreateMetrics() returned nil, the metric was already there, we're good
	// and don't split hair about 201 vs 200/204

	gctx.Status(http.StatusCreated)
}
