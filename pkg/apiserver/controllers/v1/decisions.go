package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// Format decisions for the bouncers
func FormatDecisions(decisions []*ent.Decision) []*models.Decision {
	var results []*models.Decision

	for _, dbDecision := range decisions {
		duration := dbDecision.Until.Sub(time.Now().UTC()).Round(time.Second).String()
		decision := models.Decision{
			ID:       int64(dbDecision.ID),
			Duration: &duration,
			Scenario: &dbDecision.Scenario,
			Scope:    &dbDecision.Scope,
			Value:    &dbDecision.Value,
			Type:     &dbDecision.Type,
			Origin:   &dbDecision.Origin,
			UUID:     dbDecision.UUID,
		}
		results = append(results, &decision)
	}

	return results
}

func (c *Controller) GetDecision(gctx *gin.Context) {
	var (
		results []*models.Decision
		data    []*ent.Decision
	)

	ctx := gctx.Request.Context()

	bouncerInfo, err := getBouncerFromContext(gctx)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})

		return
	}

	data, err = c.DBClient.QueryDecisionWithFilter(ctx, gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)

		return
	}

	results = FormatDecisions(data)
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

	if bouncerInfo.LastPull == nil || time.Now().UTC().Sub(*bouncerInfo.LastPull) >= time.Minute {
		if err := c.DBClient.UpdateBouncerLastPull(ctx, time.Now().UTC(), bouncerInfo.ID); err != nil {
			log.Errorf("failed to update bouncer last pull: %v", err)
		}
	}

	gctx.JSON(http.StatusOK, results)
}

func (c *Controller) DeleteDecisionById(gctx *gin.Context) {
	decisionIDStr := gctx.Param("decision_id")

	decisionID, err := strconv.Atoi(decisionIDStr)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "decision_id must be valid integer"})

		return
	}

	ctx := gctx.Request.Context()

	nbDeleted, deletedFromDB, err := c.DBClient.ExpireDecisionByID(ctx, decisionID)
	if err != nil {
		c.HandleDBErrors(gctx, err)

		return
	}

	// transform deleted decisions to be sendable to capi
	deletedDecisions := FormatDecisions(deletedFromDB)

	if c.DecisionDeleteChan != nil {
		c.DecisionDeleteChan <- deletedDecisions
	}

	deleteDecisionResp := models.DeleteDecisionResponse{
		NbDeleted: strconv.Itoa(nbDeleted),
	}

	gctx.JSON(http.StatusOK, deleteDecisionResp)
}

func (c *Controller) DeleteDecisions(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	nbDeleted, deletedFromDB, err := c.DBClient.ExpireDecisionsWithFilter(ctx, gctx.Request.URL.Query())
	if err != nil {
		c.HandleDBErrors(gctx, err)

		return
	}

	// transform deleted decisions to be sendable to capi
	deletedDecisions := FormatDecisions(deletedFromDB)

	if c.DecisionDeleteChan != nil {
		c.DecisionDeleteChan <- deletedDecisions
	}

	deleteDecisionResp := models.DeleteDecisionResponse{
		NbDeleted: nbDeleted,
	}

	gctx.JSON(http.StatusOK, deleteDecisionResp)
}

func writeStartupDecisions(gctx *gin.Context, filters map[string][]string, dbFunc func(context.Context, map[string][]string) ([]*ent.Decision, error)) error {
	// respBuffer := bytes.NewBuffer([]byte{})
	limit := 30000 // FIXME : make it configurable
	needComma := false
	lastId := 0

	ctx := gctx.Request.Context()

	limitStr := strconv.Itoa(limit)
	filters["limit"] = []string{limitStr}

	for {
		if lastId > 0 {
			lastIdStr := strconv.Itoa(lastId)
			filters["id_gt"] = []string{lastIdStr}
		}

		data, err := dbFunc(ctx, filters)
		if err != nil {
			return err
		}

		if len(data) > 0 {
			lastId = data[len(data)-1].ID

			results := FormatDecisions(data)
			for _, decision := range results {
				decisionJSON, _ := json.Marshal(decision)

				if needComma {
					// respBuffer.Write([]byte(","))
					gctx.Writer.WriteString(",")
				} else {
					needComma = true
				}
				//respBuffer.Write(decisionJSON)
				//_, err := gctx.Writer.Write(respBuffer.Bytes())
				_, err := gctx.Writer.Write(decisionJSON)
				if err != nil {
					gctx.Writer.Flush()

					return err
				}
				// respBuffer.Reset()
			}
		}

		log.Debugf("startup: %d decisions returned (limit: %d, lastid: %d)", len(data), limit, lastId)

		if len(data) < limit {
			gctx.Writer.Flush()

			break
		}
	}

	return nil
}

func writeDeltaDecisions(gctx *gin.Context, filters map[string][]string, lastPull *time.Time, dbFunc func(context.Context, *time.Time, map[string][]string) ([]*ent.Decision, error)) error {
	// respBuffer := bytes.NewBuffer([]byte{})
	limit := 30000 // FIXME : make it configurable
	needComma := false
	lastId := 0

	ctx := gctx.Request.Context()

	limitStr := strconv.Itoa(limit)
	filters["limit"] = []string{limitStr}

	for {
		if lastId > 0 {
			lastIdStr := strconv.Itoa(lastId)
			filters["id_gt"] = []string{lastIdStr}
		}

		data, err := dbFunc(ctx, lastPull, filters)
		if err != nil {
			return err
		}

		if len(data) > 0 {
			lastId = data[len(data)-1].ID

			results := FormatDecisions(data)
			for _, decision := range results {
				decisionJSON, _ := json.Marshal(decision)

				if needComma {
					// respBuffer.Write([]byte(","))
					gctx.Writer.WriteString(",")
				} else {
					needComma = true
				}
				//respBuffer.Write(decisionJSON)
				//_, err := gctx.Writer.Write(respBuffer.Bytes())
				_, err := gctx.Writer.Write(decisionJSON)
				if err != nil {
					gctx.Writer.Flush()

					return err
				}
				// respBuffer.Reset()
			}
		}

		log.Debugf("startup: %d decisions returned (limit: %d, lastid: %d)", len(data), limit, lastId)

		if len(data) < limit {
			gctx.Writer.Flush()

			break
		}
	}

	return nil
}

func (c *Controller) StreamDecisionChunked(gctx *gin.Context, bouncerInfo *ent.Bouncer, streamStartTime time.Time, filters map[string][]string) error {
	var err error

	gctx.Writer.Header().Set("Content-Type", "application/json")
	gctx.Writer.Header().Set("Transfer-Encoding", "chunked")
	gctx.Writer.WriteHeader(http.StatusOK)
	gctx.Writer.WriteString(`{"new": [`) // No need to check for errors, the doc says it always returns nil

	// if the blocker just started, return all decisions
	if val, ok := gctx.Request.URL.Query()["startup"]; ok && val[0] == "true" {
		// Active decisions
		err := writeStartupDecisions(gctx, filters, c.DBClient.QueryAllDecisionsWithFilters)
		if err != nil {
			log.Errorf("failed sending new decisions for startup: %v", err)
			gctx.Writer.WriteString(`], "deleted": []}`)
			gctx.Writer.Flush()

			return err
		}

		gctx.Writer.WriteString(`], "deleted": [`)
		// Expired decisions
		err = writeStartupDecisions(gctx, filters, c.DBClient.QueryExpiredDecisionsWithFilters)
		if err != nil {
			log.Errorf("failed sending expired decisions for startup: %v", err)
			gctx.Writer.WriteString(`]}`)
			gctx.Writer.Flush()

			return err
		}

		gctx.Writer.WriteString(`]}`)
		gctx.Writer.Flush()
	} else {
		err = writeDeltaDecisions(gctx, filters, bouncerInfo.LastPull, c.DBClient.QueryNewDecisionsSinceWithFilters)
		if err != nil {
			log.Errorf("failed sending new decisions for delta: %v", err)
			gctx.Writer.WriteString(`], "deleted": []}`)
			gctx.Writer.Flush()

			return err
		}

		gctx.Writer.WriteString(`], "deleted": [`)

		err = writeDeltaDecisions(gctx, filters, bouncerInfo.LastPull, c.DBClient.QueryExpiredDecisionsSinceWithFilters)
		if err != nil {
			log.Errorf("failed sending expired decisions for delta: %v", err)
			gctx.Writer.WriteString("]}")
			gctx.Writer.Flush()

			return err
		}

		gctx.Writer.WriteString("]}")
		gctx.Writer.Flush()
	}

	return nil
}

func (c *Controller) StreamDecisionNonChunked(gctx *gin.Context, bouncerInfo *ent.Bouncer, streamStartTime time.Time, filters map[string][]string) error {
	var (
		data []*ent.Decision
		err  error
	)

	ctx := gctx.Request.Context()

	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}

	if val, ok := gctx.Request.URL.Query()["startup"]; ok {
		if val[0] == "true" {
			data, err = c.DBClient.QueryAllDecisionsWithFilters(ctx, filters)
			if err != nil {
				log.Errorf("failed querying decisions: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})

				return err
			}
			// data = KeepLongestDecision(data)
			ret["new"] = FormatDecisions(data)

			// getting expired decisions
			data, err = c.DBClient.QueryExpiredDecisionsWithFilters(ctx, filters)
			if err != nil {
				log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})

				return err
			}

			ret["deleted"] = FormatDecisions(data)

			gctx.JSON(http.StatusOK, ret)

			return nil
		}
	}

	// getting new decisions
	data, err = c.DBClient.QueryNewDecisionsSinceWithFilters(ctx, bouncerInfo.LastPull, filters)
	if err != nil {
		log.Errorf("unable to query new decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})

		return err
	}
	// data = KeepLongestDecision(data)
	ret["new"] = FormatDecisions(data)

	since := time.Time{}
	if bouncerInfo.LastPull != nil {
		since = bouncerInfo.LastPull.Add(-2 * time.Second)
	}

	// getting expired decisions
	data, err = c.DBClient.QueryExpiredDecisionsSinceWithFilters(ctx, &since, filters) // do we want to give exactly lastPull time ?
	if err != nil {
		log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})

		return err
	}

	ret["deleted"] = FormatDecisions(data)
	gctx.JSON(http.StatusOK, ret)

	return nil
}

func (c *Controller) StreamDecision(gctx *gin.Context) {
	var err error

	streamStartTime := time.Now().UTC()

	bouncerInfo, err := getBouncerFromContext(gctx)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "not allowed"})

		return
	}

	if gctx.Request.Method == http.MethodHead {
		// For HEAD, just return as the bouncer won't get a body anyway, so no need to query the db
		// We also don't update the last pull time, as it would mess with the delta sent on the next request (if done without startup=true)
		gctx.String(http.StatusOK, "")

		return
	}

	filters := gctx.Request.URL.Query()
	if _, ok := filters["scopes"]; !ok {
		filters["scopes"] = []string{"ip,range"}
	}

	if fflag.ChunkedDecisionsStream.IsEnabled() {
		err = c.StreamDecisionChunked(gctx, bouncerInfo, streamStartTime, filters)
	} else {
		err = c.StreamDecisionNonChunked(gctx, bouncerInfo, streamStartTime, filters)
	}

	if err == nil {
		// Only update the last pull time if no error occurred when sending the decisions to avoid missing decisions
		// Do not reuse the context provided by gin because we already have sent the response to the client, so there's a chance for it to already be canceled
		if err := c.DBClient.UpdateBouncerLastPull(context.Background(), streamStartTime, bouncerInfo.ID); err != nil {
			log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
		}
	}
}
