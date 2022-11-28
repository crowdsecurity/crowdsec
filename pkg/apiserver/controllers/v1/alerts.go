package v1

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
)

func FormatOneAlert(alert *ent.Alert) *models.Alert {
	var outputAlert models.Alert
	startAt := alert.StartedAt.String()
	StopAt := alert.StoppedAt.String()

	machineID := "N/A"
	if alert.Edges.Owner != nil {
		machineID = alert.Edges.Owner.MachineId
	}

	outputAlert = models.Alert{
		ID:              int64(alert.ID),
		MachineID:       machineID,
		CreatedAt:       alert.CreatedAt.Format(time.RFC3339),
		Scenario:        &alert.Scenario,
		ScenarioVersion: &alert.ScenarioVersion,
		ScenarioHash:    &alert.ScenarioHash,
		Message:         &alert.Message,
		EventsCount:     &alert.EventsCount,
		StartAt:         &startAt,
		StopAt:          &StopAt,
		Capacity:        &alert.Capacity,
		Leakspeed:       &alert.LeakSpeed,
		Simulated:       &alert.Simulated,
		Source: &models.Source{
			Scope:     &alert.SourceScope,
			Value:     &alert.SourceValue,
			IP:        alert.SourceIp,
			Range:     alert.SourceRange,
			AsNumber:  alert.SourceAsNumber,
			AsName:    alert.SourceAsName,
			Cn:        alert.SourceCountry,
			Latitude:  alert.SourceLatitude,
			Longitude: alert.SourceLongitude,
		},
	}
	for _, eventItem := range alert.Edges.Events {
		var Metas models.Meta
		timestamp := eventItem.Time.String()
		if err := json.Unmarshal([]byte(eventItem.Serialized), &Metas); err != nil {
			log.Errorf("unable to unmarshall events meta '%s' : %s", eventItem.Serialized, err)
		}
		outputAlert.Events = append(outputAlert.Events, &models.Event{
			Timestamp: &timestamp,
			Meta:      Metas,
		})
	}
	for _, metaItem := range alert.Edges.Metas {
		outputAlert.Meta = append(outputAlert.Meta, &models.MetaItems0{
			Key:   metaItem.Key,
			Value: metaItem.Value,
		})
	}
	for _, decisionItem := range alert.Edges.Decisions {
		duration := decisionItem.Until.Sub(time.Now().UTC()).String()
		outputAlert.Decisions = append(outputAlert.Decisions, &models.Decision{
			Duration:  &duration, // transform into time.Time ?
			Scenario:  &decisionItem.Scenario,
			Type:      &decisionItem.Type,
			Scope:     &decisionItem.Scope,
			Value:     &decisionItem.Value,
			Origin:    &decisionItem.Origin,
			Simulated: outputAlert.Simulated,
			ID:        int64(decisionItem.ID),
		})
	}
	return &outputAlert
}

// FormatAlerts : Format results from the database to be swagger model compliant
func FormatAlerts(result []*ent.Alert) models.AddAlertsRequest {
	var data models.AddAlertsRequest
	for _, alertItem := range result {
		data = append(data, FormatOneAlert(alertItem))
	}
	return data
}

func (c *Controller) sendAlertToPluginChannel(alert *models.Alert, profileID uint) {
	if c.PluginChannel != nil {
	RETRY:
		for try := 0; try < 3; try++ {
			select {
			case c.PluginChannel <- csplugin.ProfileAlert{ProfileID: profileID, Alert: alert}:
				log.Debugf("alert sent to Plugin channel")
				break RETRY
			default:
				log.Warningf("Cannot send alert to Plugin channel (try: %d)", try)
				time.Sleep(time.Millisecond * 50)
			}
		}
	}
}

// CreateAlert writes the alerts received in the body to the database
func (c *Controller) CreateAlert(gctx *gin.Context) {

	var input models.AddAlertsRequest

	claims := jwt.ExtractClaims(gctx)
	// TBD: use defined rather than hardcoded key to find back owner
	machineID := claims["id"].(string)

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	if err := input.Validate(strfmt.Default); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	stopFlush := false
	for _, alert := range input {
		alert.MachineID = machineID
		if len(alert.Decisions) != 0 {
			for pIdx, profile := range c.Profiles {
				_, matched, err := profile.EvaluateProfile(alert)
				if err != nil {
					gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}
				if !matched {
					continue
				}
				c.sendAlertToPluginChannel(alert, uint(pIdx))
				if profile.Cfg.OnSuccess == "break" {
					break
				}
			}
			decision := alert.Decisions[0]
			if decision.Origin != nil && *decision.Origin == "cscli-import" {
				stopFlush = true
			}
			continue
		}

		for pIdx, profile := range c.Profiles {
			profileDecisions, matched, err := profile.EvaluateProfile(alert)
			if err != nil {
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			if !matched {
				continue
			}

			if len(alert.Decisions) == 0 { // non manual decision
				alert.Decisions = append(alert.Decisions, profileDecisions...)
			}
			profileAlert := *alert
			c.sendAlertToPluginChannel(&profileAlert, uint(pIdx))
			if profile.Cfg.OnSuccess == "break" {
				break
			}
		}
	}

	if stopFlush {
		c.DBClient.CanFlush = false
	}

	alerts, err := c.DBClient.CreateAlert(machineID, input)
	c.DBClient.CanFlush = true

	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	if c.CAPIChan != nil {
		select {
		case c.CAPIChan <- input:
			log.Debug("alert sent to CAPI channel")
		default:
			log.Warning("Cannot send alert to Central API channel")
		}
	}

	gctx.JSON(http.StatusCreated, alerts)
}

// FindAlerts: returns alerts from the database based on the specified filter
func (c *Controller) FindAlerts(gctx *gin.Context) {
	result, err := c.DBClient.QueryAlertWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	data := FormatAlerts(result)

	if gctx.Request.Method == http.MethodHead {
		gctx.String(http.StatusOK, "")
		return
	}
	gctx.JSON(http.StatusOK, data)
}

// FindAlertByID returns the alert associated with the ID
func (c *Controller) FindAlertByID(gctx *gin.Context) {
	alertIDStr := gctx.Param("alert_id")
	alertID, err := strconv.Atoi(alertIDStr)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "alert_id must be valid integer"})
		return
	}
	result, err := c.DBClient.GetAlertByID(alertID)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	data := FormatOneAlert(result)

	if gctx.Request.Method == http.MethodHead {
		gctx.String(http.StatusOK, "")
		return
	}
	gctx.JSON(http.StatusOK, data)
}

// DeleteAlertByID delete the alert associated to the ID
func (c *Controller) DeleteAlertByID(gctx *gin.Context) {
	var err error

	incomingIP := gctx.ClientIP()
	if incomingIP != "127.0.0.1" && incomingIP != "::1" && !networksContainIP(c.TrustedIPs, incomingIP) {
		gctx.JSON(http.StatusForbidden, gin.H{"message": fmt.Sprintf("access forbidden from this IP (%s)", incomingIP)})
		return
	}

	decisionIDStr := gctx.Param("alert_id")
	decisionID, err := strconv.Atoi(decisionIDStr)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "alert_id must be valid integer"})
		return
	}
	err = c.DBClient.DeleteAlertByID(decisionID)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	deleteAlertResp := models.DeleteAlertsResponse{
		NbDeleted: "1",
	}

	gctx.JSON(http.StatusOK, deleteAlertResp)
}


// DeleteAlerts deletes alerts from the database based on the specified filter
func (c *Controller) DeleteAlerts(gctx *gin.Context) {
	incomingIP := gctx.ClientIP()
	if incomingIP != "127.0.0.1" && incomingIP != "::1" && !networksContainIP(c.TrustedIPs, incomingIP) {
		gctx.JSON(http.StatusForbidden, gin.H{"message": fmt.Sprintf("access forbidden from this IP (%s)", incomingIP)})
		return
	}
	var err error
	nbDeleted, err := c.DBClient.DeleteAlertWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	deleteAlertsResp := models.DeleteAlertsResponse{
		NbDeleted: strconv.Itoa(nbDeleted),
	}
	gctx.JSON(http.StatusOK, deleteAlertsResp)
}

func networksContainIP(networks []net.IPNet, ip string) bool {
	parsedIP := net.ParseIP(ip)
	for _, network := range networks {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}
