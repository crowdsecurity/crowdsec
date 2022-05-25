package v1

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func FormatDecisions(decisions []*ent.Decision) ([]*models.Decision, error) {
	var results []*models.Decision
	for _, dbDecision := range decisions {
		duration := dbDecision.Until.Sub(time.Now().UTC()).String()
		decision := models.Decision{
			ID:       int64(dbDecision.ID),
			Duration: &duration,
			Scenario: &dbDecision.Scenario,
			Scope:    &dbDecision.Scope,
			Value:    &dbDecision.Value,
			Type:     &dbDecision.Type,
			Origin:   &dbDecision.Origin,
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
		return
	}
	/*let's follow a naive logic : when a bouncer queries /decisions, if the answer is empty, we assume there is no decision for this ip/user/...,
	but if it's non-empty, it means that there is one or more decisions for this target*/
	if len(results) > 0 {
		PrometheusBouncersHasNonEmptyDecision(gctx)
	} else {
		PrometheusBouncersHasEmptyDecision(gctx)
	}

	if gctx.Request.Method == "HEAD" {
		gctx.String(http.StatusOK, "")
		return
	}
	gctx.JSON(http.StatusOK, results)
}

func (c *Controller) DeleteDecisionById(gctx *gin.Context) {
	var err error

	decisionIDStr := gctx.Param("decision_id")
	decisionID, err := strconv.Atoi(decisionIDStr)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "decision_id must be valid integer"})
		return
	}
	err = c.DBClient.SoftDeleteDecisionByID(decisionID)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	deleteDecisionResp := models.DeleteDecisionResponse{
		NbDeleted: "1",
	}

	gctx.JSON(http.StatusOK, deleteDecisionResp)
}

func (c *Controller) DeleteDecisions(gctx *gin.Context) {
	var err error

	nbDeleted, err := c.DBClient.SoftDeleteDecisionsWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}
	deleteDecisionResp := models.DeleteDecisionResponse{
		NbDeleted: nbDeleted,
	}

	gctx.JSON(http.StatusOK, deleteDecisionResp)
}

func (c *Controller) StreamDecision(gctx *gin.Context) {
	var data []*ent.Decision
	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}

	val := gctx.Request.Header.Get(c.APIKeyHeader)
	hashedKey := sha512.New()
	hashedKey.Write([]byte(val))
	hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))
	bouncerInfo, err := c.DBClient.SelectBouncer(hashStr)
	if err != nil {
		if _, ok := err.(*ent.NotFoundError); ok {
			gctx.JSON(http.StatusForbidden, gin.H{"message": err.Error()})
		} else {
			gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})
		}
		return
	}

	if bouncerInfo == nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})
		return
	}

	filters := gctx.Request.URL.Query()
	if _, ok := filters["scopes"]; !ok {
		filters["scopes"] = []string{"ip,range"}
	}

	// if the blocker just start, return all decisions
	if val, ok := gctx.Request.URL.Query()["startup"]; ok {
		if val[0] == "true" {
			data, err := c.DBClient.QueryAllDecisionsWithFilters(filters)
			if err != nil {
				log.Errorf("failed querying decisions: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			ret["new"], err = FormatDecisions(data)
			if err != nil {
				log.Errorf("unable to format expired decision for '%s' : %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			// getting expired decisions
			data, err = c.DBClient.QueryExpiredDecisionsWithFilters(filters)
			if err != nil {
				log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			ret["deleted"], err = FormatDecisions(data)
			if err != nil {
				log.Errorf("unable to format expired decision for '%s' : %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			if err := c.DBClient.UpdateBouncerLastPull(time.Now().UTC(), bouncerInfo.ID); err != nil {
				log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			if gctx.Request.Method == "HEAD" {
				gctx.String(http.StatusOK, "")
				return
			}
			gctx.JSON(http.StatusOK, ret)
			return
		}
	}

	// getting new decisions
	data, err = c.DBClient.QueryNewDecisionsSinceWithFilters(bouncerInfo.LastPull, filters)
	if err != nil {
		log.Errorf("unable to query new decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	ret["new"], err = FormatDecisions(data)
	if err != nil {
		log.Errorf("unable to format new decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	// getting expired decisions
	data, err = c.DBClient.QueryExpiredDecisionsSinceWithFilters(bouncerInfo.LastPull.Add((-2 * time.Second)), filters) // do we want to give exactly lastPull time ?
	if err != nil {
		log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	ret["deleted"], err = FormatDecisions(data)
	if err != nil {
		log.Errorf("unable to format expired decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	if err := c.DBClient.UpdateBouncerLastPull(time.Now().UTC(), bouncerInfo.ID); err != nil {
		log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	gctx.JSON(http.StatusOK, ret)
}
