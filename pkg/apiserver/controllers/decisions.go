package controllers

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"strconv"
)

func FormatDecisions(decisions []*ent.Decision) ([]*models.Decision, error) {
	var results []*models.Decision
	for _, dbDecision := range decisions {
		duration := dbDecision.Until.Sub(time.Now())
		decision := models.Decision{
			DecisionID: fmt.Sprintf("%d", dbDecision.ID),
			Duration:   duration.String(),
			EndIP:      dbDecision.EndIP,
			StartIP:    dbDecision.StartIP,
			Scenario:   dbDecision.Scenario,
			Scope:      dbDecision.Scope,
			Target:     dbDecision.Target,
			Type:       dbDecision.Type,
		}
		results = append(results, &decision)
	}
	return results, nil
}

func (c *Controller) GetDecision(gctx *gin.Context) {
	var err error
	var results []*models.Decision
	var data []*ent.Decision

	data, err = c.DBClient.QueryDecisionWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	results, err = FormatDecisions(data)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}

	gctx.JSON(http.StatusOK, results)
}

func (c *Controller) DeleteDecisionById(gctx *gin.Context) {
	var err error

	decisionIdStr := gctx.Param("decision_id")
	decisionId, err := strconv.Atoi(decisionIdStr)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "decision_id must be valid integer"})
		return
	}
	err = c.DBClient.DeleteDecisionById(decisionId)
	if err != nil {
		c.HandleDBErrors(gctx, err)
	}

	gctx.JSON(http.StatusOK, gin.H{"message": "successfully deleted"})
	return
}

func (c *Controller) DeleteDecisions(gctx *gin.Context) {
	var err error

	nbDeleted, err := c.DBClient.DeleteDecisionsWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
	}

	gctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d deleted decisions", nbDeleted)})
}

func (c *Controller) StreamDecision(gctx *gin.Context) {
	var data []*ent.Decision

	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}

	// if the blocker just start, return all decisions
	if _, ok := gctx.Request.URL.Query()["startup"]; ok {
		data, err := c.DBClient.QueryAllDecisions()
		if err != nil {
			log.Errorf("failed querying decisions: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		ret["new"], err = FormatDecisions(data)
		gctx.JSON(http.StatusOK, ret)
		return
	}

	val, _ := gctx.Request.Header[c.APIKeyHeader]
	hashedKey := sha256.New()
	hashedKey.Write([]byte(val[0]))
	hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))
	lastPull, err := c.DBClient.LastBlockerPull(hashStr)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}

	lastPullTime, err := time.Parse(time.RFC3339, lastPull)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}

	// getting new decisions
	data, err = c.DBClient.QueryNewDecisionsSince(lastPullTime)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}
	ret["new"], err = FormatDecisions(data)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}

	// getting expired decisions
	data, err = c.DBClient.QueryExpiredDecisions()
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}
	ret["deleted"], err = FormatDecisions(data)
	if err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
	}

	gctx.JSON(http.StatusOK, ret)
	return
}
