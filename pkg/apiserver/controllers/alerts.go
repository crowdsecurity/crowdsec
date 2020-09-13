package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func FormatAlerts(result []*ent.Alert) []models.Alert {
	var data []models.Alert
	for _, alertItem := range result {
		var outputAlert models.Alert
		outputAlert = models.Alert{
			MachineID:   alertItem.Edges.Owner.MachineId,
			Scenario:    alertItem.Scenario,
			AlertID:     alertItem.BucketId,
			Message:     alertItem.Message,
			EventsCount: alertItem.EventsCount,
			StartAt:     alertItem.StartedAt.String(),
			StopAt:      alertItem.StoppedAt.String(),
			Capacity:    alertItem.Capacity,
			Leakspeed:   alertItem.LeakSpeed,
			Source: &models.Source{
				Scope:     alertItem.SourceScope,
				Value:     alertItem.SourceValue,
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
			if err := json.Unmarshal([]byte(eventItem.Serialized), &Metas); err != nil {
				log.Errorf("unable to unmarshall events meta '%s' : %s", eventItem.Serialized, err)
			}
			outputEvents = append(outputEvents, &models.Event{
				Timestamp: eventItem.Time.String(),
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
			outputDecisions = append(outputDecisions, &models.Decision{
				Duration: decisionItem.Until.Sub(time.Now()).String(), // transform into time.Time ?
				Scenario: decisionItem.Scenario,
				Type:     decisionItem.Type,
				StartIP:  decisionItem.StartIP,
				EndIP:    decisionItem.EndIP,
				Scope:    decisionItem.Scope,
				Target:   decisionItem.Target,
			})
			outputAlert.Decisions = outputDecisions
		}
		data = append(data, outputAlert)
	}
	return data
}

func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input []models.Alert
	var alertID int
	var responses []string
	var err error

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, alertItem := range input {
		alertID, err = c.DBClient.CreateAlert(&alertItem)
		if err != nil {
			c.HandleDBErrors(gctx, err)
			return
		}
		responses = append(responses, strconv.Itoa(alertID))
	}
	gctx.JSON(http.StatusOK, responses)
	return
}

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

func (c *Controller) DeleteAlerts(gctx *gin.Context) {
	var err error
	deleted, err := c.DBClient.DeleteAlertWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
	}

	gctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d deleted alerts", len(deleted))})
	return
}
