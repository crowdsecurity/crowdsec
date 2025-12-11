package v1

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/router"
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

func (c *Controller) GetDecision(w http.ResponseWriter, r *http.Request) {
	var (
		results []*models.Decision
		data    []*ent.Decision
	)

	ctx := r.Context()

	bouncerInfo, err := getBouncerFromContext(r)
	if err != nil {
		router.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "not allowed"})

		return
	}

	data, err = c.DBClient.QueryDecisionWithFilter(ctx, r.URL.Query())
	if err != nil {
		c.HandleDBErrors(w, err)

		return
	}

	results = FormatDecisions(data)
	/*let's follow a naive logic : when a bouncer queries /decisions, if the answer is empty, we assume there is no decision for this ip/user/...,
	but if it's non-empty, it means that there is one or more decisions for this target*/
	if len(results) > 0 {
		PrometheusBouncersHasNonEmptyDecision(r)
	} else {
		PrometheusBouncersHasEmptyDecision(r)
	}

	if r.Method == http.MethodHead {
		router.String(w, http.StatusOK, "")

		return
	}

	if bouncerInfo.LastPull == nil || time.Now().UTC().Sub(*bouncerInfo.LastPull) >= time.Minute {
		if err := c.DBClient.UpdateBouncerLastPull(ctx, time.Now().UTC(), bouncerInfo.ID); err != nil {
			log.Errorf("failed to update bouncer last pull: %v", err)
		}
	}

	router.WriteJSON(w, http.StatusOK, results)
}

func (c *Controller) DeleteDecisionById(w http.ResponseWriter, r *http.Request) {
	decisionIDStr := router.PathValue(r, "decision_id")

	decisionID, err := strconv.Atoi(decisionIDStr)
	if err != nil {
		router.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "decision_id must be valid integer"})

		return
	}

	ctx := r.Context()

	nbDeleted, deletedFromDB, err := c.DBClient.ExpireDecisionByID(ctx, decisionID)
	if err != nil {
		c.HandleDBErrors(w, err)

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

	router.WriteJSON(w, http.StatusOK, deleteDecisionResp)
}

func (c *Controller) DeleteDecisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nbDeleted, deletedFromDB, err := c.DBClient.ExpireDecisionsWithFilter(ctx, r.URL.Query())
	if err != nil {
		c.HandleDBErrors(w, err)

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

	router.WriteJSON(w, http.StatusOK, deleteDecisionResp)
}

func writeStartupDecisions(w http.ResponseWriter, r *http.Request, filters map[string][]string, dbFunc func(context.Context, map[string][]string) ([]*ent.Decision, error)) error {
	// respBuffer := bytes.NewBuffer([]byte{})
	limit := 30000 // FIXME : make it configurable
	needComma := false
	lastId := 0

	ctx := r.Context()
	flusher, hasFlusher := w.(http.Flusher)

	// Work on a copy of filters to avoid mutating the shared map
	filtersCopy := make(map[string][]string, len(filters)+2)
	maps.Copy(filtersCopy, filters)

	limitStr := strconv.Itoa(limit)
	filtersCopy["limit"] = []string{limitStr}

	for {
		if lastId > 0 {
			lastIdStr := strconv.Itoa(lastId)
			filtersCopy["id_gt"] = []string{lastIdStr}
		} else {
			// Clear id_gt if it exists from previous iteration
			delete(filtersCopy, "id_gt")
		}

		data, err := dbFunc(ctx, filtersCopy)
		if err != nil {
			return err
		}

		if len(data) > 0 {
			lastId = data[len(data)-1].ID

			results := FormatDecisions(data)
			for _, decision := range results {
				decisionJSON, _ := json.Marshal(decision)

				if needComma {
					if _, err := w.Write([]byte(",")); err != nil {
						return err
					}
				} else {
					needComma = true
				}
				_, err := w.Write(decisionJSON)
				if err != nil {
					if hasFlusher {
						flusher.Flush()
					}

					return err
				}
			}
		}

		log.Debugf("startup: %d decisions returned (limit: %d, lastid: %d)", len(data), limit, lastId)

		if len(data) < limit {
			if hasFlusher {
				flusher.Flush()
			}

			break
		}
	}

	return nil
}

func writeDeltaDecisions(w http.ResponseWriter, r *http.Request, filters map[string][]string, lastPull *time.Time, dbFunc func(context.Context, *time.Time, map[string][]string) ([]*ent.Decision, error)) error {
	// respBuffer := bytes.NewBuffer([]byte{})
	limit := 30000 // FIXME : make it configurable
	needComma := false
	lastId := 0

	ctx := r.Context()
	flusher, hasFlusher := w.(http.Flusher)

	// Work on a copy of filters to avoid mutating the shared map
	filtersCopy := make(map[string][]string, len(filters)+2)
	maps.Copy(filtersCopy, filters)

	limitStr := strconv.Itoa(limit)
	filtersCopy["limit"] = []string{limitStr}

	for {
		if lastId > 0 {
			lastIdStr := strconv.Itoa(lastId)
			filtersCopy["id_gt"] = []string{lastIdStr}
		} else {
			// Clear id_gt if it exists from previous iteration
			delete(filtersCopy, "id_gt")
		}

		data, err := dbFunc(ctx, lastPull, filtersCopy)
		if err != nil {
			return err
		}

		if len(data) > 0 {
			lastId = data[len(data)-1].ID

			results := FormatDecisions(data)
			for _, decision := range results {
				decisionJSON, _ := json.Marshal(decision)

				if needComma {
					if _, err := w.Write([]byte(",")); err != nil {
						return err
					}
				} else {
					needComma = true
				}
				_, err := w.Write(decisionJSON)
				if err != nil {
					if hasFlusher {
						flusher.Flush()
					}

					return err
				}
			}
		}

		log.Debugf("startup: %d decisions returned (limit: %d, lastid: %d)", len(data), limit, lastId)

		if len(data) < limit {
			if hasFlusher {
				flusher.Flush()
			}

			break
		}
	}

	return nil
}

// writeStartupResponse writes startup decisions (both active and expired) to the response
func (c *Controller) writeStartupResponse(w http.ResponseWriter, r *http.Request, filters map[string][]string, flusher http.Flusher, hasFlusher bool) error {
	// Active decisions
	err := writeStartupDecisions(w, r, filters, c.DBClient.QueryAllDecisionsWithFilters)
	if err != nil {
		log.Errorf("failed sending new decisions for startup: %v", err)
		_, _ = w.Write([]byte(`], "deleted": []}`))
		if hasFlusher {
			flusher.Flush()
		}
		return err
	}

	if _, err := w.Write([]byte(`], "deleted": [`)); err != nil {
		return err
	}

	// Expired decisions
	err = writeStartupDecisions(w, r, filters, c.DBClient.QueryExpiredDecisionsWithFilters)
	if err != nil {
		log.Errorf("failed sending expired decisions for startup: %v", err)
		_, _ = w.Write([]byte(`]}`))
		if hasFlusher {
			flusher.Flush()
		}
		return err
	}

	if _, err := w.Write([]byte(`]}`)); err != nil {
		return err
	}
	if hasFlusher {
		flusher.Flush()
	}
	return nil
}

// writeDeltaResponse writes delta decisions (both new and expired) to the response
func (c *Controller) writeDeltaResponse(w http.ResponseWriter, r *http.Request, bouncerInfo *ent.Bouncer, filters map[string][]string, flusher http.Flusher, hasFlusher bool) error {
	err := writeDeltaDecisions(w, r, filters, bouncerInfo.LastPull, c.DBClient.QueryNewDecisionsSinceWithFilters)
	if err != nil {
		log.Errorf("failed sending new decisions for delta: %v", err)
		_, _ = w.Write([]byte(`], "deleted": []}`))
		if hasFlusher {
			flusher.Flush()
		}
		return err
	}

	if _, err := w.Write([]byte(`], "deleted": [`)); err != nil {
		return err
	}

	err = writeDeltaDecisions(w, r, filters, bouncerInfo.LastPull, c.DBClient.QueryExpiredDecisionsSinceWithFilters)
	if err != nil {
		log.Errorf("failed sending expired decisions for delta: %v", err)
		_, _ = w.Write([]byte("]}"))
		if hasFlusher {
			flusher.Flush()
		}
		return err
	}

	if _, err := w.Write([]byte("]}")); err != nil {
		return err
	}
	if hasFlusher {
		flusher.Flush()
	}
	return nil
}

func (c *Controller) StreamDecisionChunked(w http.ResponseWriter, r *http.Request, bouncerInfo *ent.Bouncer, streamStartTime time.Time, filters map[string][]string) error {
	flusher, hasFlusher := w.(http.Flusher)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"new": [`)); err != nil { // Write initial JSON structure
		return err
	}

	// if the blocker just started, return all decisions
	val, ok := r.URL.Query()["startup"]
	if ok && val[0] == "true" {
		return c.writeStartupResponse(w, r, filters, flusher, hasFlusher)
	}

	return c.writeDeltaResponse(w, r, bouncerInfo, filters, flusher, hasFlusher)
}

func (c *Controller) StreamDecisionNonChunked(w http.ResponseWriter, r *http.Request, bouncerInfo *ent.Bouncer, streamStartTime time.Time, filters map[string][]string) error {
	var (
		data []*ent.Decision
		err  error
	)

	ctx := r.Context()

	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}

	if val, ok := r.URL.Query()["startup"]; ok {
		if val[0] == "true" {
			data, err = c.DBClient.QueryAllDecisionsWithFilters(ctx, filters)
			if err != nil {
				log.Errorf("failed querying decisions: %v", err)
				router.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})

				return err
			}
			// data = KeepLongestDecision(data)
			ret["new"] = FormatDecisions(data)

			// getting expired decisions
			data, err = c.DBClient.QueryExpiredDecisionsWithFilters(ctx, filters)
			if err != nil {
				log.Errorf("unable to query expired decision for '%s' : %v", bouncerInfo.Name, err)
				router.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})

				return err
			}

			ret["deleted"] = FormatDecisions(data)

			router.WriteJSON(w, http.StatusOK, ret)

			return nil
		}
	}

	// getting new decisions
	data, err = c.DBClient.QueryNewDecisionsSinceWithFilters(ctx, bouncerInfo.LastPull, filters)
	if err != nil {
		log.Errorf("unable to query new decision for '%s' : %v", bouncerInfo.Name, err)
		router.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})

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
		router.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})

		return err
	}

	ret["deleted"] = FormatDecisions(data)
	router.WriteJSON(w, http.StatusOK, ret)

	return nil
}

func (c *Controller) StreamDecision(w http.ResponseWriter, r *http.Request) {
	var err error

	streamStartTime := time.Now().UTC()

	bouncerInfo, err := getBouncerFromContext(r)
	if err != nil {
		router.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "not allowed"})

		return
	}

	if r.Method == http.MethodHead {
		// For HEAD, just return as the bouncer won't get a body anyway, so no need to query the db
		// We also don't update the last pull time, as it would mess with the delta sent on the next request (if done without startup=true)
		router.String(w, http.StatusOK, "")

		return
	}

	filters := r.URL.Query()
	if _, ok := filters["scopes"]; !ok {
		filters["scopes"] = []string{"ip,range"}
	}

	if fflag.ChunkedDecisionsStream.IsEnabled() {
		err = c.StreamDecisionChunked(w, r, bouncerInfo, streamStartTime, filters)
	} else {
		err = c.StreamDecisionNonChunked(w, r, bouncerInfo, streamStartTime, filters)
	}

	if err == nil {
		// Only update the last pull time if no error occurred when sending the decisions to avoid missing decisions
		// Use a background context since we've already sent the response and the request context may be canceled
		//nolint:contextcheck // We intentionally use context.Background() here since the response is already sent
		if err := c.DBClient.UpdateBouncerLastPull(context.Background(), streamStartTime, bouncerInfo.ID); err != nil {
			log.Errorf("unable to update bouncer '%s' pull: %v", bouncerInfo.Name, err)
		}
	}
}
