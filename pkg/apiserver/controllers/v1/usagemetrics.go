package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// updateBaseMetrics updates the base metrics for a machine or bouncer
func (c *Controller) updateBaseMetrics(ctx context.Context, machineID string, bouncer *ent.Bouncer, baseMetrics models.BaseMetrics, hubItems models.HubItems, datasources map[string]int64) error {
	switch {
	case machineID != "":
		return c.DBClient.MachineUpdateBaseMetrics(ctx, machineID, baseMetrics, hubItems, datasources)
	case bouncer != nil:
		return c.DBClient.BouncerUpdateBaseMetrics(ctx, bouncer.Name, bouncer.Type, baseMetrics)
	default:
		return errors.New("no machineID or bouncerName set")
	}
}

// UsageMetrics receives metrics from log processors and remediation components
func (c *Controller) UsageMetrics(gctx *gin.Context) {
	var input models.AllMetrics

	logger := log.WithField("func", "UsageMetrics")

	// parse the payload

	if err := gctx.ShouldBindJSON(&input); err != nil {
		logger.Errorf("Failed to bind json: %s", err)
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})

		return
	}

	if err := input.Validate(strfmt.Default); err != nil {
		// work around a nuisance in the generated code
		cleanErr := RepeatedPrefixError{
			OriginalError: err,
			Prefix:        "validation failure list:\n",
		}
		logger.Errorf("Failed to validate usage metrics: %s", cleanErr)
		gctx.JSON(http.StatusUnprocessableEntity, gin.H{"message": cleanErr.Error()})

		return
	}

	var (
		generatedType metric.GeneratedType
		generatedBy   string
	)

	bouncer, _ := getBouncerFromContext(gctx)
	if bouncer != nil {
		logger.Tracef("Received usage metris for bouncer: %s", bouncer.Name)

		generatedType = metric.GeneratedTypeRC
		generatedBy = bouncer.Name
	}

	machineID, _ := getMachineIDFromContext(gctx)
	if machineID != "" {
		logger.Tracef("Received usage metrics for log processor: %s", machineID)

		generatedType = metric.GeneratedTypeLP
		generatedBy = machineID
	}

	if generatedBy == "" {
		// how did we get here?
		logger.Error("No machineID or bouncer in request context after authentication")
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": "No machineID or bouncer in request context after authentication"})

		return
	}

	if machineID != "" && bouncer != nil {
		logger.Errorf("Payload has both machineID and bouncer")
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "Payload has both LP and RC data"})

		return
	}

	var (
		payload     map[string]any
		baseMetrics models.BaseMetrics
		hubItems    models.HubItems
		datasources map[string]int64
	)

	switch len(input.LogProcessors) {
	case 0:
		if machineID != "" {
			logger.Errorf("Missing log processor data")
			gctx.JSON(http.StatusBadRequest, gin.H{"message": "Missing log processor data"})

			return
		}
	case 1:
		// the final slice can't have more than one item,
		// guaranteed by the swagger schema
		item0 := input.LogProcessors[0]

		err := item0.Validate(strfmt.Default)
		if err != nil {
			logger.Errorf("Failed to validate log processor data: %s", err)
			gctx.JSON(http.StatusUnprocessableEntity, gin.H{"message": err.Error()})

			return
		}

		payload = map[string]any{
			"metrics": item0.Metrics,
		}
		baseMetrics = item0.BaseMetrics
		hubItems = item0.HubItems
		datasources = item0.Datasources
	default:
		logger.Errorf("Payload has more than one log processor")
		// this is not checked in the swagger schema
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "Payload has more than one log processor"})

		return
	}

	switch len(input.RemediationComponents) {
	case 0:
		if bouncer != nil {
			logger.Errorf("Missing remediation component data")
			gctx.JSON(http.StatusBadRequest, gin.H{"message": "Missing remediation component data"})

			return
		}
	case 1:
		item0 := input.RemediationComponents[0]

		err := item0.Validate(strfmt.Default)
		if err != nil {
			logger.Errorf("Failed to validate remediation component data: %s", err)
			gctx.JSON(http.StatusUnprocessableEntity, gin.H{"message": err.Error()})

			return
		}

		payload = map[string]any{
			"type":    item0.Type,
			"metrics": item0.Metrics,
		}
		baseMetrics = item0.BaseMetrics
	default:
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "Payload has more than one remediation component"})
		return
	}

	if baseMetrics.Os == nil {
		baseMetrics.Os = &models.OSversion{
			Name:    ptr.Of(""),
			Version: ptr.Of(""),
		}
	}

	ctx := gctx.Request.Context()

	err := c.updateBaseMetrics(ctx, machineID, bouncer, baseMetrics, hubItems, datasources)
	if err != nil {
		logger.Errorf("Failed to update base metrics: %s", err)
		c.HandleDBErrors(gctx, err)

		return
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.Errorf("Failed to serialize usage metrics: %s", err)
		c.HandleDBErrors(gctx, err)

		return
	}

	receivedAt := time.Now().UTC()

	if _, err := c.DBClient.CreateMetric(ctx, generatedType, generatedBy, receivedAt, string(jsonPayload)); err != nil {
		logger.Error(err)
		c.HandleDBErrors(gctx, err)

		return
	}

	// if CreateMetrics() returned nil, the metric was already there, we're good
	// and don't split hair about 201 vs 200/204

	gctx.Status(http.StatusCreated)
}
