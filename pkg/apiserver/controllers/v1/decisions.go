package v1

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

// Format decisions for the bouncers, and deduplicate them by keeping only the longest one
func FormatDecisions(decisions []*ent.Decision, dedup bool) []*models.Decision {
	var results []*models.Decision

	seen := make(map[string]struct{}, 0)

	for _, dbDecision := range decisions {
		if dedup {
			key := dbDecision.Value + dbDecision.Scope + dbDecision.Type
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
		}
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
	return results
}

func (c *Controller) GetDecision(gctx *gin.Context) {
	var err error
	var results []*models.Decision
	var data []*ent.Decision

	bouncerInfo, err := getBouncerFromContext(gctx)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})
		return
	}

	data, err = c.DBClient.QueryDecisionWithFilter(gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	results = FormatDecisions(data, false)
	/*let's follow a naive logic : when a bouncer queries /decisions, if the answer is empty, we assume there is no decision for this ip/user/...,
	but if it's non-empty, it means that there is one or more decisions for this target*/
	if len(results) > 0 {
		PrometheusBouncersHasNonEmptyDecision(gctx)
	} else {
		PrometheusBouncersHasEmptyDecision(gctx)
	}

	if gctx.Request.Method == http.MethodHead {
		gctx.String(http.StatusOK, "")
		return
	}

	if time.Now().UTC().Sub(bouncerInfo.LastPull) >= time.Minute {
		if err := c.DBClient.UpdateBouncerLastPull(time.Now().UTC(), bouncerInfo.ID); err != nil {
			log.Errorf("failed to update bouncer last pull: %v", err)
		}
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
	nbDeleted, err := c.DBClient.SoftDeleteDecisionByID(decisionID)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	deleteDecisionResp := models.DeleteDecisionResponse{
		NbDeleted: strconv.Itoa(nbDeleted),
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
	var err error
	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}
	streamStartTime := time.Now().UTC()

	bouncerInfo, err := getBouncerFromContext(gctx)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})
		return
	}

	filters := gctx.Request.URL.Query()
	if _, ok := filters["scopes"]; !ok {
		filters["scopes"] = []string{"ip,range"}
	}

	dedup := true
	if v, ok := filters["dedup"]; ok && v[0] == "false" {
		dedup = false
	}

	limit := 3000
	offset := 0
	start := true
	needComma := false
	// if the blocker just start, return all decisions
	if val, ok := gctx.Request.URL.Query()["startup"]; ok {
		if val[0] == "true" {
			for {
				limitStr := fmt.Sprintf("%d", limit)
				filters["limit"] = []string{limitStr}
				offsetStr := fmt.Sprintf("%d", offset)
				filters["offset"] = []string{offsetStr}

				if start {
					gctx.Writer.Header().Set("Content-Type", "application/json")
					gctx.Writer.Header().Set("Transfer-Encoding", "chunked")
					gctx.Writer.WriteHeader(http.StatusOK)
					gctx.Writer.Write([]byte(`{"new": [`))
					start = false
				}

				data, _ = c.DBClient.QueryAllDecisionsWithFilters(filters)
				if len(data) > 0 {
					results := FormatDecisions(data, dedup)
					for _, decision := range results {
						decisionJSON, _ := json.Marshal(decision)
						if needComma {
							gctx.Writer.Write([]byte(","))
						} else {
							needComma = true
						}
						gctx.Writer.Write(decisionJSON)
					}
				}
				log.Infof("startup: %d decisions returned (limit: %d, offset: %d)", len(data), limit, offset)
				//TODO: handle when the number of decisions is divisible by limit
				if len(data) < limit {
					gctx.Writer.Write([]byte(`], "deleted": [`))
					gctx.Writer.Write([]byte("]}"))
					gctx.Writer.Flush()
					return
				}
				offset += len(data)
			}

			/*if err != nil {
				log.Errorf("failed querying decisions: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}*/
			//data = KeepLongestDecision(data)
			//ret["new"] = FormatDecisions(data, dedup)

			// getting expired decisions
			/*data, err = c.DBClient.QueryExpiredDecisionsWithFilters(filters)
			if err != nil {
				log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			ret["deleted"] = FormatDecisions(data, dedup)

			if err := c.DBClient.UpdateBouncerLastPull(streamStartTime, bouncerInfo.ID); err != nil {
				log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			if gctx.Request.Method == http.MethodHead {
				gctx.String(http.StatusOK, "")
				return
			}
			gctx.JSON(http.StatusOK, ret)
			return*/
		}
	}

	// getting new decisions
	data, err = c.DBClient.QueryNewDecisionsSinceWithFilters(bouncerInfo.LastPull, filters)
	if err != nil {
		log.Errorf("unable to query new decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	//data = KeepLongestDecision(data)
	ret["new"] = FormatDecisions(data, dedup)

	// getting expired decisions
	data, err = c.DBClient.QueryExpiredDecisionsSinceWithFilters(bouncerInfo.LastPull.Add((-2 * time.Second)), filters) // do we want to give exactly lastPull time ?
	if err != nil {
		log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	ret["deleted"] = FormatDecisions(data, dedup)

	if err := c.DBClient.UpdateBouncerLastPull(streamStartTime, bouncerInfo.ID); err != nil {
		log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	gctx.JSON(http.StatusOK, ret)
}
