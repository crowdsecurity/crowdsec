package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
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

func formatOneDecision(dbDecision *ent.Decision) *models.Decision {
	duration := dbDecision.Until.Sub(time.Now().UTC()).Round(time.Second).String()

	return &models.Decision{
		ID:       int64(dbDecision.ID),
		Duration: &duration,
		Scenario: &dbDecision.Scenario,
		Scope:    &dbDecision.Scope,
		Value:    &dbDecision.Value,
		Type:     &dbDecision.Type,
		Origin:   &dbDecision.Origin,
		UUID:     dbDecision.UUID,
	}
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
		NbDeleted: strconv.Itoa(nbDeleted),
	}

	gctx.JSON(http.StatusOK, deleteDecisionResp)
}

// writeDecisions streams the decisions returned by query into the array the caller has already
// opened, paginating by id from startID. A startup resync passes 0, a stream delta passes the
// bouncer cursor: both are the same query, they only differ in where they start.
func writeDecisions(gctx *gin.Context, now time.Time, filters map[string][]string, startID int, query func(context.Context, time.Time, map[string][]string) ([]*ent.Decision, error)) error {
	limit := 30000 // FIXME : make it configurable
	needComma := false
	lastId := startID

	ctx := gctx.Request.Context()

	// We write to a buffer instead of directly to the writer to avoid the \n added by enc.Encode()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	limitStr := strconv.Itoa(limit)
	filters["limit"] = []string{limitStr}
	// callers reuse the same filters map across calls; clear any pagination cursor left by a previous call.
	delete(filters, "id_gt")

	for {
		if lastId > 0 {
			lastIdStr := strconv.Itoa(lastId)
			filters["id_gt"] = []string{lastIdStr}
		}

		data, err := query(ctx, now, filters)
		if err != nil {
			return err
		}

		for _, d := range data {
			if needComma {
				gctx.Writer.WriteString(",")
			} else {
				needComma = true
			}

			buf.Reset()
			if err := enc.Encode(formatOneDecision(d)); err != nil {
				gctx.Writer.Flush()

				return err
			}
			// Encode() appends a trailing newline; strip it to keep the wire format compact.
			b := buf.Bytes()
			if n := len(b); n > 0 && b[n-1] == '\n' {
				b = b[:n-1]
			}
			if _, err := gctx.Writer.Write(b); err != nil {
				gctx.Writer.Flush()

				return err
			}
		}

		if len(data) > 0 {
			lastId = data[len(data)-1].ID
		}

		log.Debugf("stream: %d decisions returned (limit: %d, lastid: %d)", len(data), limit, lastId)

		if len(data) < limit {
			gctx.Writer.Flush()

			break
		}
	}

	return nil
}

func (c *Controller) streamDecisions(gctx *gin.Context, bouncerInfo *ent.Bouncer, now time.Time, filters map[string][]string, cursor int, startup bool) error {
	gctx.Writer.Header().Set("Content-Type", "application/json")
	gctx.Writer.Header().Set("Transfer-Encoding", "chunked")
	gctx.Writer.WriteHeader(http.StatusOK)
	gctx.Writer.WriteString(`{"new": [`) // No need to check for errors, the doc says it always returns nil

	// Active decisions. A startup resync is this same query with a zero cursor.
	if err := writeDecisions(gctx, now, filters, cursor, c.DBClient.QueryAllDecisionsWithFilters); err != nil {
		log.Errorf("failed sending new decisions: %v", err)
		gctx.Writer.WriteString(`], "deleted": []}`)
		gctx.Writer.Flush()

		return err
	}

	gctx.Writer.WriteString(`], "deleted": [`)

	// Expired decisions. Unlike the active ones these are keyed on until, not on the cursor:
	// a decision expires when the clock passes it, with no write to order against.
	expired := c.DBClient.QueryExpiredDecisionsWithFilters

	if !startup {
		// Use a 2-second overlap to avoid missing decisions that expired around the last pull time
		var expiredSince *time.Time
		if bouncerInfo.LastPull != nil {
			since := bouncerInfo.LastPull.Add(-2 * time.Second)
			expiredSince = &since
		}

		expired = func(ctx context.Context, now time.Time, filters map[string][]string) ([]*ent.Decision, error) {
			return c.DBClient.QueryExpiredDecisionsSinceWithFilters(ctx, now, expiredSince, filters)
		}
	}

	if err := writeDecisions(gctx, now, filters, 0, expired); err != nil {
		log.Errorf("failed sending expired decisions: %v", err)
		gctx.Writer.WriteString(`]}`)
		gctx.Writer.Flush()

		return err
	}

	gctx.Writer.WriteString(`]}`)
	gctx.Writer.Flush()

	return nil
}

func (c *Controller) StreamDecision(gctx *gin.Context) {
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

	val, ok := filters["startup"]
	startup := ok && val[0] == "true"

	// Read the cursor before streaming anything: a decision we cannot see yet belongs to an
	// uncommitted transaction and will get a higher id, so this value cannot step over it.
	// A wall clock timestamp cannot make that promise, which is why last_pull is not used here.
	latestID, err := c.DBClient.LatestDecisionID(gctx.Request.Context())
	if err != nil {
		c.HandleDBErrors(gctx, err)

		return
	}

	cursor := bouncerInfo.StreamCursor
	// A cursor past the end of the table means the decisions were rewound under us: a partial
	// restore, or MySQL < 8.0 recomputing AUTO_INCREMENT after the highest rows were deleted.
	if startup || cursor > latestID {
		cursor = 0
	}

	err = c.streamDecisions(gctx, bouncerInfo, streamStartTime, filters, cursor, startup)

	if err == nil {
		// Only update the pull state if no error occurred when sending the decisions to avoid missing decisions
		// Do not reuse the context provided by gin because we already have sent the response to the client, so there's a chance for it to already be canceled
		if err := c.DBClient.UpdateBouncerStreamPull(context.Background(), streamStartTime, latestID, bouncerInfo.ID); err != nil {
			log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
		}
	}
}
