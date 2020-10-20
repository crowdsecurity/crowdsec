package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
)

// FormatAlerts : Format results from the database to be swagger model compliant
func FormatAlerts(result []*ent.Alert) models.AddAlertsRequest {
	var data models.AddAlertsRequest
	for _, alertItem := range result {
		var outputAlert models.Alert
		startAt := alertItem.StartedAt.String()
		StopAt := alertItem.StoppedAt.String()
		outputAlert = models.Alert{
			ID:          int64(alertItem.ID),
			MachineID:   alertItem.Edges.Owner.MachineId,
			CreatedAt:   alertItem.CreatedAt.Format(time.RFC3339),
			Scenario:    &alertItem.Scenario,
			Message:     &alertItem.Message,
			EventsCount: &alertItem.EventsCount,
			StartAt:     &startAt,
			StopAt:      &StopAt,
			Capacity:    &alertItem.Capacity,
			Leakspeed:   &alertItem.LeakSpeed,
			Simulated:   &alertItem.Simulated,
			Source: &models.Source{
				Scope:     &alertItem.SourceScope,
				Value:     &alertItem.SourceValue,
				IP:        alertItem.SourceIp,
				Range:     alertItem.SourceRange,
				AsNumber:  alertItem.SourceAsNumber,
				AsName:    alertItem.SourceAsName,
				Cn:        alertItem.SourceCountry,
				Latitude:  alertItem.SourceLatitude,
				Longitude: alertItem.SourceLongitude,
			},
		}
		for _, eventItem := range alertItem.Edges.Events {
			var outputEvents []*models.Event
			var Metas models.Meta
			timestamp := eventItem.Time.String()
			if err := json.Unmarshal([]byte(eventItem.Serialized), &Metas); err != nil {
				log.Errorf("unable to unmarshall events meta '%s' : %s", eventItem.Serialized, err)
			}
			outputEvents = append(outputEvents, &models.Event{
				Timestamp: &timestamp,
				Meta:      Metas,
			})
			outputAlert.Events = outputEvents
		}
		for _, metaItem := range alertItem.Edges.Metas {
			var outputMetas models.Meta
			outputMetas = append(outputMetas, &models.MetaItems0{
				Key:   metaItem.Key,
				Value: metaItem.Value,
			})
			outputAlert.Meta = outputMetas
		}
		for _, decisionItem := range alertItem.Edges.Decisions {
			var outputDecisions []*models.Decision
			duration := decisionItem.Until.Sub(time.Now()).String()
			outputDecisions = append(outputDecisions, &models.Decision{
				Duration:  &duration, // transform into time.Time ?
				Scenario:  &decisionItem.Scenario,
				Type:      &decisionItem.Type,
				StartIP:   decisionItem.StartIP,
				EndIP:     decisionItem.EndIP,
				Scope:     &decisionItem.Scope,
				Value:     &decisionItem.Value,
				Origin:    &decisionItem.Origin,
				Simulated: outputAlert.Simulated,
				ID:        int64(decisionItem.ID),
			})
			outputAlert.Decisions = outputDecisions
		}
		data = append(data, &outputAlert)
	}
	return data
}

// CreateAlert : write received alerts in body to the database
func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input models.AddAlertsRequest

	claims := jwt.ExtractClaims(gctx)
	/*TBD : use defines rather than hardcoded key to find back owner*/
	machineID := claims["id"].(string)

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	if err := input.Validate(strfmt.Default); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	for _, alert := range input {
		decisions, err := csprofiles.EvaluateProfiles(c.Profiles, alert)
		if err != nil {
			gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		alert.Decisions = decisions
	}

	alerts, err := c.DBClient.CreateAlertBulk(machineID, input)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	gctx.JSON(http.StatusOK, alerts)
	return
}

// FindAlerts : return alerts from database based on the specified filter
func (c *Controller) FindAlerts(gctx *gin.Context) {
	result, err := c.DBClient.QueryAlertWithFilter(gctx.Request.URL.Query())

	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	data := FormatAlerts(result)

	gctx.JSON(http.StatusOK, data)
	return
}

// DeleteAlerts : delete alerts from database based on the specified filter
func (c *Controller) DeleteAlerts(gctx *gin.Context) {
	var err error
	deleted, err := c.DBClient.DeleteAlertWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
	}

	gctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d deleted alerts", len(deleted))})
	return
}
