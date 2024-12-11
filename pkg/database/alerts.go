package database

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	paginationSize      = 100 // used to queryAlert to avoid 'too many SQL variable'
	defaultLimit        = 100 // default limit of element to returns when query alerts
	alertCreateBulkSize = 50  // bulk size when create alerts
	maxLockRetries      = 10  // how many times to retry a bulk operation when sqlite3.ErrBusy is encountered
)

// CreateOrUpdateAlert is specific to PAPI : It checks if alert already exists, otherwise inserts it
// if alert already exists, it checks it associated decisions already exists
// if some associated decisions are missing (ie. previous insert ended up in error) it inserts them
func (c *Client) CreateOrUpdateAlert(ctx context.Context, machineID string, alertItem *models.Alert) (string, error) {
	if alertItem.UUID == "" {
		return "", errors.New("alert UUID is empty")
	}

	alerts, err := c.Ent.Alert.Query().Where(alert.UUID(alertItem.UUID)).WithDecisions().All(ctx)

	if err != nil && !ent.IsNotFound(err) {
		return "", fmt.Errorf("unable to query alerts for uuid %s: %w", alertItem.UUID, err)
	}

	// alert wasn't found, insert it (expected hotpath)
	if ent.IsNotFound(err) || len(alerts) == 0 {
		alertIDs, err := c.CreateAlert(ctx, machineID, []*models.Alert{alertItem})
		if err != nil {
			return "", fmt.Errorf("unable to create alert: %w", err)
		}

		return alertIDs[0], nil
	}

	// this should never happen
	if len(alerts) > 1 {
		return "", fmt.Errorf("multiple alerts found for uuid %s", alertItem.UUID)
	}

	log.Infof("Alert %s already exists, checking associated decisions", alertItem.UUID)

	// alert is found, check for any missing decisions

	newUuids := make([]string, len(alertItem.Decisions))
	for i, decItem := range alertItem.Decisions {
		newUuids[i] = decItem.UUID
	}

	foundAlert := alerts[0]
	foundUuids := make([]string, len(foundAlert.Edges.Decisions))

	for i, decItem := range foundAlert.Edges.Decisions {
		foundUuids[i] = decItem.UUID
	}

	sort.Strings(foundUuids)
	sort.Strings(newUuids)

	missingUuids := []string{}

	for idx, uuid := range newUuids {
		if len(foundUuids) < idx+1 || uuid != foundUuids[idx] {
			log.Warningf("Decision with uuid %s not found in alert %s", uuid, foundAlert.UUID)
			missingUuids = append(missingUuids, uuid)
		}
	}

	if len(missingUuids) == 0 {
		log.Warningf("alert %s was already complete with decisions %+v", alertItem.UUID, foundUuids)
		return "", nil
	}

	// add any and all missing decisions based on their uuids
	// prepare missing decisions
	missingDecisions := []*models.Decision{}

	for _, uuid := range missingUuids {
		for _, newDecision := range alertItem.Decisions {
			if newDecision.UUID == uuid {
				missingDecisions = append(missingDecisions, newDecision)
			}
		}
	}

	// add missing decisions
	log.Debugf("Adding %d missing decisions to alert %s", len(missingDecisions), foundAlert.UUID)

	decisionBuilders := []*ent.DecisionCreate{}

	for _, decisionItem := range missingDecisions {
		var (
			start_ip, start_sfx, end_ip, end_sfx int64
			sz                                   int
		)

		/*if the scope is IP or Range, convert the value to integers */
		if strings.ToLower(*decisionItem.Scope) == "ip" || strings.ToLower(*decisionItem.Scope) == "range" {
			sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(*decisionItem.Value)
			if err != nil {
				log.Errorf("invalid addr/range '%s': %s", *decisionItem.Value, err)
				continue
			}
		}

		decisionDuration, err := time.ParseDuration(*decisionItem.Duration)
		if err != nil {
			log.Warningf("invalid duration %s for decision %s", *decisionItem.Duration, decisionItem.UUID)
			continue
		}

		// use the created_at from the alert instead
		alertTime, err := time.Parse(time.RFC3339, alertItem.CreatedAt)
		if err != nil {
			log.Errorf("unable to parse alert time %s : %s", alertItem.CreatedAt, err)

			alertTime = time.Now()
		}

		decisionUntil := alertTime.UTC().Add(decisionDuration)

		decisionBuilder := c.Ent.Decision.Create().
			SetUntil(decisionUntil).
			SetScenario(*decisionItem.Scenario).
			SetType(*decisionItem.Type).
			SetStartIP(start_ip).
			SetStartSuffix(start_sfx).
			SetEndIP(end_ip).
			SetEndSuffix(end_sfx).
			SetIPSize(int64(sz)).
			SetValue(*decisionItem.Value).
			SetScope(*decisionItem.Scope).
			SetOrigin(*decisionItem.Origin).
			SetSimulated(*alertItem.Simulated).
			SetUUID(decisionItem.UUID)

		decisionBuilders = append(decisionBuilders, decisionBuilder)
	}

	decisions := []*ent.Decision{}

	builderChunks := slicetools.Chunks(decisionBuilders, c.decisionBulkSize)

	for _, builderChunk := range builderChunks {
		decisionsCreateRet, err := c.Ent.Decision.CreateBulk(builderChunk...).Save(ctx)
		if err != nil {
			return "", fmt.Errorf("creating alert decisions: %w", err)
		}

		decisions = append(decisions, decisionsCreateRet...)
	}

	// now that we bulk created missing decisions, let's update the alert

	decisionChunks := slicetools.Chunks(decisions, c.decisionBulkSize)

	for _, decisionChunk := range decisionChunks {
		err = c.Ent.Alert.Update().Where(alert.UUID(alertItem.UUID)).AddDecisions(decisionChunk...).Exec(ctx)
		if err != nil {
			return "", fmt.Errorf("updating alert %s: %w", alertItem.UUID, err)
		}
	}

	return "", nil
}

// UpdateCommunityBlocklist is called to update either the community blocklist (or other lists the user subscribed to)
// it takes care of creating the new alert with the associated decisions, and it will as well deleted the "older" overlapping decisions:
// 1st pull, you get decisions [1,2,3]. it inserts [1,2,3]
// 2nd pull, you get decisions [1,2,3,4]. it inserts [1,2,3,4] and will try to delete [1,2,3,4] with a different alert ID and same origin
func (c *Client) UpdateCommunityBlocklist(ctx context.Context, alertItem *models.Alert) (int, int, int, error) {
	if alertItem == nil {
		return 0, 0, 0, errors.New("nil alert")
	}

	if alertItem.StartAt == nil {
		return 0, 0, 0, errors.New("nil start_at")
	}

	startAtTime, err := time.Parse(time.RFC3339, *alertItem.StartAt)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(ParseTimeFail, "start_at field time '%s': %s", *alertItem.StartAt, err)
	}

	if alertItem.StopAt == nil {
		return 0, 0, 0, errors.New("nil stop_at")
	}

	stopAtTime, err := time.Parse(time.RFC3339, *alertItem.StopAt)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(ParseTimeFail, "stop_at field time '%s': %s", *alertItem.StopAt, err)
	}

	ts, err := time.Parse(time.RFC3339, *alertItem.StopAt)
	if err != nil {
		c.Log.Errorf("While parsing StartAt of item %s : %s", *alertItem.StopAt, err)

		ts = time.Now().UTC()
	}

	alertB := c.Ent.Alert.
		Create().
		SetScenario(*alertItem.Scenario).
		SetMessage(*alertItem.Message).
		SetEventsCount(*alertItem.EventsCount).
		SetStartedAt(startAtTime).
		SetStoppedAt(stopAtTime).
		SetSourceScope(*alertItem.Source.Scope).
		SetSourceValue(*alertItem.Source.Value).
		SetSourceIp(alertItem.Source.IP).
		SetSourceRange(alertItem.Source.Range).
		SetSourceAsNumber(alertItem.Source.AsNumber).
		SetSourceAsName(alertItem.Source.AsName).
		SetSourceCountry(alertItem.Source.Cn).
		SetSourceLatitude(alertItem.Source.Latitude).
		SetSourceLongitude(alertItem.Source.Longitude).
		SetCapacity(*alertItem.Capacity).
		SetLeakSpeed(*alertItem.Leakspeed).
		SetSimulated(*alertItem.Simulated).
		SetScenarioVersion(*alertItem.ScenarioVersion).
		SetScenarioHash(*alertItem.ScenarioHash).
		SetRemediation(true) // it's from CAPI, we always have decisions

	alertRef, err := alertB.Save(ctx)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(BulkError, "error creating alert : %s", err)
	}

	if len(alertItem.Decisions) == 0 {
		return alertRef.ID, 0, 0, nil
	}

	txClient, err := c.Ent.Tx(ctx)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(BulkError, "error creating transaction : %s", err)
	}

	DecOrigin := CapiMachineID

	if *alertItem.Decisions[0].Origin == CapiMachineID || *alertItem.Decisions[0].Origin == CapiListsMachineID {
		DecOrigin = *alertItem.Decisions[0].Origin
	} else {
		log.Warningf("unexpected origin %s", *alertItem.Decisions[0].Origin)
	}

	deleted := 0
	inserted := 0

	decisionBuilders := make([]*ent.DecisionCreate, 0, len(alertItem.Decisions))
	valueList := make([]string, 0, len(alertItem.Decisions))

	for _, decisionItem := range alertItem.Decisions {
		var (
			start_ip, start_sfx, end_ip, end_sfx int64
			sz                                   int
		)

		if decisionItem.Duration == nil {
			log.Warning("nil duration in community decision")
			continue
		}

		duration, err := time.ParseDuration(*decisionItem.Duration)
		if err != nil {
			rollbackErr := txClient.Rollback()
			if rollbackErr != nil {
				log.Errorf("rollback error: %s", rollbackErr)
			}

			return 0, 0, 0, errors.Wrapf(ParseDurationFail, "decision duration '%+v' : %s", *decisionItem.Duration, err)
		}

		if decisionItem.Scope == nil {
			log.Warning("nil scope in community decision")
			continue
		}

		/*if the scope is IP or Range, convert the value to integers */
		if strings.ToLower(*decisionItem.Scope) == "ip" || strings.ToLower(*decisionItem.Scope) == "range" {
			sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(*decisionItem.Value)
			if err != nil {
				rollbackErr := txClient.Rollback()
				if rollbackErr != nil {
					log.Errorf("rollback error: %s", rollbackErr)
				}

				return 0, 0, 0, errors.Wrapf(InvalidIPOrRange, "invalid addr/range %s : %s", *decisionItem.Value, err)
			}
		}

		/*bulk insert some new decisions*/
		decisionBuilder := c.Ent.Decision.Create().
			SetUntil(ts.Add(duration)).
			SetScenario(*decisionItem.Scenario).
			SetType(*decisionItem.Type).
			SetStartIP(start_ip).
			SetStartSuffix(start_sfx).
			SetEndIP(end_ip).
			SetEndSuffix(end_sfx).
			SetIPSize(int64(sz)).
			SetValue(*decisionItem.Value).
			SetScope(*decisionItem.Scope).
			SetOrigin(*decisionItem.Origin).
			SetSimulated(*alertItem.Simulated).
			SetOwner(alertRef)

		decisionBuilders = append(decisionBuilders, decisionBuilder)

		/*for bulk delete of duplicate decisions*/
		if decisionItem.Value == nil {
			log.Warning("nil value in community decision")
			continue
		}

		valueList = append(valueList, *decisionItem.Value)
	}

	deleteChunks := slicetools.Chunks(valueList, c.decisionBulkSize)

	for _, deleteChunk := range deleteChunks {
		// Deleting older decisions from capi
		deletedDecisions, err := txClient.Decision.Delete().
			Where(decision.And(
				decision.OriginEQ(DecOrigin),
				decision.Not(decision.HasOwnerWith(alert.IDEQ(alertRef.ID))),
				decision.ValueIn(deleteChunk...),
			)).Exec(ctx)
		if err != nil {
			rollbackErr := txClient.Rollback()
			if rollbackErr != nil {
				log.Errorf("rollback error: %s", rollbackErr)
			}

			return 0, 0, 0, fmt.Errorf("while deleting older community blocklist decisions: %w", err)
		}

		deleted += deletedDecisions
	}

	builderChunks := slicetools.Chunks(decisionBuilders, c.decisionBulkSize)

	for _, builderChunk := range builderChunks {
		insertedDecisions, err := txClient.Decision.CreateBulk(builderChunk...).Save(ctx)
		if err != nil {
			rollbackErr := txClient.Rollback()
			if rollbackErr != nil {
				log.Errorf("rollback error: %s", rollbackErr)
			}

			return 0, 0, 0, fmt.Errorf("while bulk creating decisions: %w", err)
		}

		inserted += len(insertedDecisions)
	}

	log.Debugf("deleted %d decisions for %s vs %s", deleted, DecOrigin, *alertItem.Decisions[0].Origin)

	err = txClient.Commit()
	if err != nil {
		rollbackErr := txClient.Rollback()
		if rollbackErr != nil {
			log.Errorf("rollback error: %s", rollbackErr)
		}

		return 0, 0, 0, fmt.Errorf("error committing transaction: %w", err)
	}

	return alertRef.ID, inserted, deleted, nil
}

func (c *Client) createDecisionChunk(ctx context.Context, simulated bool, stopAtTime time.Time, decisions []*models.Decision) ([]*ent.Decision, error) {
	decisionCreate := []*ent.DecisionCreate{}

	for _, decisionItem := range decisions {
		var (
			start_ip, start_sfx, end_ip, end_sfx int64
			sz                                   int
		)

		duration, err := time.ParseDuration(*decisionItem.Duration)
		if err != nil {
			return nil, errors.Wrapf(ParseDurationFail, "decision duration '%+v' : %s", *decisionItem.Duration, err)
		}

		/*if the scope is IP or Range, convert the value to integers */
		if strings.ToLower(*decisionItem.Scope) == "ip" || strings.ToLower(*decisionItem.Scope) == "range" {
			sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(*decisionItem.Value)
			if err != nil {
				log.Errorf("invalid addr/range '%s': %s", *decisionItem.Value, err)
				continue
			}
		}

		newDecision := c.Ent.Decision.Create().
			SetUntil(stopAtTime.Add(duration)).
			SetScenario(*decisionItem.Scenario).
			SetType(*decisionItem.Type).
			SetStartIP(start_ip).
			SetStartSuffix(start_sfx).
			SetEndIP(end_ip).
			SetEndSuffix(end_sfx).
			SetIPSize(int64(sz)).
			SetValue(*decisionItem.Value).
			SetScope(*decisionItem.Scope).
			SetOrigin(*decisionItem.Origin).
			SetSimulated(simulated).
			SetUUID(decisionItem.UUID)

		decisionCreate = append(decisionCreate, newDecision)
	}

	if len(decisionCreate) == 0 {
		return nil, nil
	}

	ret, err := c.Ent.Decision.CreateBulk(decisionCreate...).Save(ctx)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *Client) createAlertChunk(ctx context.Context, machineID string, owner *ent.Machine, alerts []*models.Alert) ([]string, error) {
	alertBuilders := []*ent.AlertCreate{}
	alertDecisions := [][]*ent.Decision{}

	for _, alertItem := range alerts {
		var (
			metas  []*ent.Meta
			events []*ent.Event
		)

		startAtTime, err := time.Parse(time.RFC3339, *alertItem.StartAt)
		if err != nil {
			c.Log.Errorf("creating alert: Failed to parse startAtTime '%s', defaulting to now: %s", *alertItem.StartAt, err)

			startAtTime = time.Now().UTC()
		}

		stopAtTime, err := time.Parse(time.RFC3339, *alertItem.StopAt)
		if err != nil {
			c.Log.Errorf("creating alert: Failed to parse stopAtTime '%s', defaulting to now: %s", *alertItem.StopAt, err)

			stopAtTime = time.Now().UTC()
		}

		/*display proper alert in logs*/
		for _, disp := range alertItem.FormatAsStrings(machineID, log.StandardLogger()) {
			c.Log.Info(disp)
		}

		// let's track when we strip or drop data, notify outside of loop to avoid spam
		stripped := false
		dropped := false

		if len(alertItem.Events) > 0 {
			eventBulk := make([]*ent.EventCreate, len(alertItem.Events))

			for i, eventItem := range alertItem.Events {
				ts, err := time.Parse(time.RFC3339, *eventItem.Timestamp)
				if err != nil {
					c.Log.Errorf("creating alert: Failed to parse event timestamp '%s', defaulting to now: %s", *eventItem.Timestamp, err)

					ts = time.Now().UTC()
				}

				marshallMetas, err := json.Marshal(eventItem.Meta)
				if err != nil {
					return nil, errors.Wrapf(MarshalFail, "event meta '%v' : %s", eventItem.Meta, err)
				}

				// the serialized field is too big, let's try to progressively strip it
				if event.SerializedValidator(string(marshallMetas)) != nil {
					stripped = true

					valid := false
					stripSize := 2048

					for !valid && stripSize > 0 {
						for _, serializedItem := range eventItem.Meta {
							if len(serializedItem.Value) > stripSize*2 {
								serializedItem.Value = serializedItem.Value[:stripSize] + "<stripped>"
							}
						}

						marshallMetas, err = json.Marshal(eventItem.Meta)
						if err != nil {
							return nil, errors.Wrapf(MarshalFail, "event meta '%v' : %s", eventItem.Meta, err)
						}

						if event.SerializedValidator(string(marshallMetas)) == nil {
							valid = true
						}

						stripSize /= 2
					}

					// nothing worked, drop it
					if !valid {
						dropped = true
						stripped = false
						marshallMetas = []byte("")
					}
				}

				eventBulk[i] = c.Ent.Event.Create().
					SetTime(ts).
					SetSerialized(string(marshallMetas))
			}

			if stripped {
				c.Log.Warningf("stripped 'serialized' field (machine %s / scenario %s)", machineID, *alertItem.Scenario)
			}

			if dropped {
				c.Log.Warningf("dropped 'serialized' field (machine %s / scenario %s)", machineID, *alertItem.Scenario)
			}

			events, err = c.Ent.Event.CreateBulk(eventBulk...).Save(ctx)
			if err != nil {
				return nil, errors.Wrapf(BulkError, "creating alert events: %s", err)
			}
		}

		if len(alertItem.Meta) > 0 {
			metaBulk := make([]*ent.MetaCreate, len(alertItem.Meta))

			for i, metaItem := range alertItem.Meta {
				key := metaItem.Key
				value := metaItem.Value

				if len(metaItem.Value) > 4095 {
					c.Log.Warningf("truncated meta %s: value too long", metaItem.Key)

					value = value[:4095]
				}

				if len(metaItem.Key) > 255 {
					c.Log.Warningf("truncated meta %s: key too long", metaItem.Key)

					key = key[:255]
				}

				metaBulk[i] = c.Ent.Meta.Create().
					SetKey(key).
					SetValue(value)
			}

			metas, err = c.Ent.Meta.CreateBulk(metaBulk...).Save(ctx)
			if err != nil {
				c.Log.Warningf("error creating alert meta: %s", err)
			}
		}

		decisions := []*ent.Decision{}

		decisionChunks := slicetools.Chunks(alertItem.Decisions, c.decisionBulkSize)
		for _, decisionChunk := range decisionChunks {
			decisionRet, err := c.createDecisionChunk(ctx, *alertItem.Simulated, stopAtTime, decisionChunk)
			if err != nil {
				return nil, fmt.Errorf("creating alert decisions: %w", err)
			}

			decisions = append(decisions, decisionRet...)
		}

		discarded := len(alertItem.Decisions) - len(decisions)
		if discarded > 0 {
			c.Log.Warningf("discarded %d decisions for %s", discarded, alertItem.UUID)
		}

		// if all decisions were discarded, discard the alert too
		if discarded > 0 && len(decisions) == 0 {
			c.Log.Warningf("dropping alert %s with invalid decisions", alertItem.UUID)
			continue
		}

		alertBuilder := c.Ent.Alert.
			Create().
			SetScenario(*alertItem.Scenario).
			SetMessage(*alertItem.Message).
			SetEventsCount(*alertItem.EventsCount).
			SetStartedAt(startAtTime).
			SetStoppedAt(stopAtTime).
			SetSourceScope(*alertItem.Source.Scope).
			SetSourceValue(*alertItem.Source.Value).
			SetSourceIp(alertItem.Source.IP).
			SetSourceRange(alertItem.Source.Range).
			SetSourceAsNumber(alertItem.Source.AsNumber).
			SetSourceAsName(alertItem.Source.AsName).
			SetSourceCountry(alertItem.Source.Cn).
			SetSourceLatitude(alertItem.Source.Latitude).
			SetSourceLongitude(alertItem.Source.Longitude).
			SetCapacity(*alertItem.Capacity).
			SetLeakSpeed(*alertItem.Leakspeed).
			SetSimulated(*alertItem.Simulated).
			SetScenarioVersion(*alertItem.ScenarioVersion).
			SetScenarioHash(*alertItem.ScenarioHash).
			SetRemediation(alertItem.Remediation).
			SetUUID(alertItem.UUID).
			AddEvents(events...).
			AddMetas(metas...)

		if owner != nil {
			alertBuilder.SetOwner(owner)
		}

		alertBuilders = append(alertBuilders, alertBuilder)
		alertDecisions = append(alertDecisions, decisions)
	}

	if len(alertBuilders) == 0 {
		log.Warningf("no alerts to create, discarded?")
		return nil, nil
	}

	alertsCreateBulk, err := c.Ent.Alert.CreateBulk(alertBuilders...).Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(BulkError, "bulk creating alert : %s", err)
	}

	ret := make([]string, len(alertsCreateBulk))
	for i, a := range alertsCreateBulk {
		ret[i] = strconv.Itoa(a.ID)

		d := alertDecisions[i]
		decisionsChunk := slicetools.Chunks(d, c.decisionBulkSize)

		for _, d2 := range decisionsChunk {
			retry := 0

			for retry < maxLockRetries {
				// so much for the happy path... but sqlite3 errors work differently
				_, err := c.Ent.Alert.Update().Where(alert.IDEQ(a.ID)).AddDecisions(d2...).Save(ctx)
				if err == nil {
					break
				}

				if sqliteErr, ok := err.(sqlite3.Error); ok {
					if sqliteErr.Code == sqlite3.ErrBusy {
						// sqlite3.Error{
						//   Code:         5,
						//   ExtendedCode: 5,
						//   SystemErrno:  0,
						//   err:          "database is locked",
						// }
						retry++
						log.Warningf("while updating decisions, sqlite3.ErrBusy: %s, retry %d of %d", err, retry, maxLockRetries)
						time.Sleep(1 * time.Second)

						continue
					}
				}

				return nil, fmt.Errorf("error while updating decisions: %w", err)
			}
		}
	}

	return ret, nil
}

func (c *Client) CreateAlert(ctx context.Context, machineID string, alertList []*models.Alert) ([]string, error) {
	var (
		owner *ent.Machine
		err   error
	)

	if machineID != "" {
		owner, err = c.QueryMachineByID(ctx, machineID)
		if err != nil {
			if !errors.Is(err, UserNotExists) {
				return nil, fmt.Errorf("machine '%s': %w", machineID, err)
			}

			c.Log.Debugf("creating alert: machine %s doesn't exist", machineID)

			owner = nil
		}
	}

	c.Log.Debugf("writing %d items", len(alertList))

	alertChunks := slicetools.Chunks(alertList, alertCreateBulkSize)
	alertIDs := []string{}

	for _, alertChunk := range alertChunks {
		ids, err := c.createAlertChunk(ctx, machineID, owner, alertChunk)
		if err != nil {
			return nil, fmt.Errorf("machine '%s': %w", machineID, err)
		}

		alertIDs = append(alertIDs, ids...)
	}

	if owner != nil {
		err = owner.Update().SetLastPush(time.Now().UTC()).Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("machine '%s': %w", machineID, err)
		}
	}

	return alertIDs, nil
}

func handleSimulatedFilter(filter map[string][]string, predicates *[]predicate.Alert) {
	/* the simulated filter is a bit different : if it's not present *or* set to false, specifically exclude records with simulated to true */
	if v, ok := filter["simulated"]; ok && v[0] == "false" {
		*predicates = append(*predicates, alert.SimulatedEQ(false))
	}
}

func handleOriginFilter(filter map[string][]string, predicates *[]predicate.Alert) {
	if _, ok := filter["origin"]; ok {
		filter["include_capi"] = []string{"true"}
	}
}

func handleScopeFilter(scope string, predicates *[]predicate.Alert) {
	if strings.ToLower(scope) == "ip" {
		scope = types.Ip
	} else if strings.ToLower(scope) == "range" {
		scope = types.Range
	}

	*predicates = append(*predicates, alert.SourceScopeEQ(scope))
}

func handleTimeFilters(param, value string, predicates *[]predicate.Alert) error {
	duration, err := ParseDuration(value)
	if err != nil {
		return fmt.Errorf("while parsing duration: %w", err)
	}

	timePoint := time.Now().UTC().Add(-duration)
	if timePoint.IsZero() {
		return fmt.Errorf("empty time now() - %s", timePoint.String())
	}

	switch param {
	case "since":
		*predicates = append(*predicates, alert.StartedAtGTE(timePoint))
	case "created_before":
		*predicates = append(*predicates, alert.CreatedAtLTE(timePoint))
	case "until":
		*predicates = append(*predicates, alert.StartedAtLTE(timePoint))
	}

	return nil
}

func handleIPv4Predicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPLTE(start_ip)),
			alert.HasDecisionsWith(decision.EndIPGTE(end_ip)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			alert.HasDecisionsWith(decision.StartIPGTE(start_ip)),
			alert.HasDecisionsWith(decision.EndIPLTE(end_ip)),
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
		))
	}
}

func handleIPv6Predicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) {
	if contains { // decision contains {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			alert.Or(
				// decision.start_ip < query.start_ip
				alert.HasDecisionsWith(decision.StartIPLT(start_ip)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
					// decision.start_suffix <= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixLTE(start_sfx)),
				),
			),
			alert.Or(
				// decision.end_ip > query.end_ip
				alert.HasDecisionsWith(decision.EndIPGT(end_ip)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
					// decision.end_suffix >= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixGTE(end_sfx)),
				),
			),
		))
	} else { // decision is contained within {start_ip,end_ip}
		*predicates = append(*predicates, alert.And(
			// matching addr size
			alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			alert.Or(
				// decision.start_ip > query.start_ip
				alert.HasDecisionsWith(decision.StartIPGT(start_ip)),
				alert.And(
					// decision.start_ip == query.start_ip
					alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
					// decision.start_suffix >= query.start_suffix
					alert.HasDecisionsWith(decision.StartSuffixGTE(start_sfx)),
				),
			),
			alert.Or(
				// decision.end_ip < query.end_ip
				alert.HasDecisionsWith(decision.EndIPLT(end_ip)),
				alert.And(
					// decision.end_ip == query.end_ip
					alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
					// decision.end_suffix <= query.end_suffix
					alert.HasDecisionsWith(decision.EndSuffixLTE(end_sfx)),
				),
			),
		))
	}
}

func handleIPPredicates(ip_sz int, contains bool, start_ip, start_sfx, end_ip, end_sfx int64, predicates *[]predicate.Alert) error {
	if ip_sz == 4 {
		handleIPv4Predicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, predicates)
	} else if ip_sz == 16 {
		handleIPv6Predicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, predicates)
	} else if ip_sz != 0 {
		return errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}

	return nil
}

func handleIncludeCapiFilter(value string, predicates *[]predicate.Alert) error {
	if value == "false" {
		*predicates = append(*predicates, alert.And(
			// do not show alerts with active decisions having origin CAPI or lists
			alert.And(
				alert.Not(alert.HasDecisionsWith(decision.OriginEQ(types.CAPIOrigin))),
				alert.Not(alert.HasDecisionsWith(decision.OriginEQ(types.ListOrigin))),
			),
			alert.Not(
				alert.And(
					// do not show neither alerts with no decisions if the Source Scope is lists: or CAPI
					alert.Not(alert.HasDecisions()),
					alert.Or(
						alert.SourceScopeHasPrefix(types.ListOrigin+":"),
						alert.SourceScopeEQ(types.CommunityBlocklistPullSourceScope),
					),
				),
			),
		))
	} else if value != "true" {
		log.Errorf("invalid bool '%s' for include_capi", value)
	}

	return nil
}

func AlertPredicatesFromFilter(filter map[string][]string) ([]predicate.Alert, error) {
	predicates := make([]predicate.Alert, 0)

	var (
		err                                  error
		start_ip, start_sfx, end_ip, end_sfx int64
		hasActiveDecision                    bool
		ip_sz                                int
	)

	contains := true

	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/

	handleSimulatedFilter(filter, &predicates)
	handleOriginFilter(filter, &predicates)

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scope":
			handleScopeFilter(value[0], &predicates)
		case "value":
			predicates = append(predicates, alert.SourceValueEQ(value[0]))
		case "scenario":
			predicates = append(predicates, alert.HasDecisionsWith(decision.ScenarioEQ(value[0])))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		case "since", "created_before", "until":
			if err := handleTimeFilters(param, value[0], &predicates); err != nil {
				return nil, err
			}
		case "decision_type":
			predicates = append(predicates, alert.HasDecisionsWith(decision.TypeEQ(value[0])))
		case "origin":
			predicates = append(predicates, alert.HasDecisionsWith(decision.OriginEQ(value[0])))
		case "include_capi": // allows to exclude one or more specific origins
			if err = handleIncludeCapiFilter(value[0], &predicates); err != nil {
				return nil, err
			}
		case "has_active_decision":
			if hasActiveDecision, err = strconv.ParseBool(value[0]); err != nil {
				return nil, errors.Wrapf(ParseType, "'%s' is not a boolean: %s", value[0], err)
			}

			if hasActiveDecision {
				predicates = append(predicates, alert.HasDecisionsWith(decision.UntilGTE(time.Now().UTC())))
			} else {
				predicates = append(predicates, alert.Not(alert.HasDecisions()))
			}
		case "limit":
			continue
		case "sort":
			continue
		case "simulated":
			continue
		case "with_decisions":
			continue
		default:
			return nil, errors.Wrapf(InvalidFilter, "Filter parameter '%s' is unknown (=%s)", param, value[0])
		}
	}

	if err := handleIPPredicates(ip_sz, contains, start_ip, start_sfx, end_ip, end_sfx, &predicates); err != nil {
		return nil, err
	}

	return predicates, nil
}

func BuildAlertRequestFromFilter(alerts *ent.AlertQuery, filter map[string][]string) (*ent.AlertQuery, error) {
	preds, err := AlertPredicatesFromFilter(filter)
	if err != nil {
		return nil, err
	}

	return alerts.Where(preds...), nil
}

func (c *Client) AlertsCountPerScenario(ctx context.Context, filters map[string][]string) (map[string]int, error) {
	var res []struct {
		Scenario string
		Count    int
	}

	query := c.Ent.Alert.Query()

	query, err := BuildAlertRequestFromFilter(query, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to build alert request: %w", err)
	}

	err = query.GroupBy(alert.FieldScenario).Aggregate(ent.Count()).Scan(ctx, &res)
	if err != nil {
		return nil, fmt.Errorf("failed to count alerts per scenario: %w", err)
	}

	counts := make(map[string]int)

	for _, r := range res {
		counts[r.Scenario] = r.Count
	}

	return counts, nil
}

func (c *Client) TotalAlerts(ctx context.Context) (int, error) {
	return c.Ent.Alert.Query().Count(ctx)
}

func (c *Client) QueryAlertWithFilter(ctx context.Context, filter map[string][]string) ([]*ent.Alert, error) {
	sort := "DESC" // we sort by desc by default

	if val, ok := filter["sort"]; ok {
		if val[0] != "ASC" && val[0] != "DESC" {
			c.Log.Errorf("invalid 'sort' parameter: %s", val)
		} else {
			sort = val[0]
		}
	}

	limit := defaultLimit

	if val, ok := filter["limit"]; ok {
		limitConv, err := strconv.Atoi(val[0])
		if err != nil {
			return nil, errors.Wrapf(QueryFail, "bad limit in parameters: %s", val)
		}

		limit = limitConv
	}

	offset := 0
	ret := make([]*ent.Alert, 0)

	for {
		alerts := c.Ent.Alert.Query()

		alerts, err := BuildAlertRequestFromFilter(alerts, filter)
		if err != nil {
			return nil, err
		}

		// only if with_decisions is present and set to false, we exclude this
		if val, ok := filter["with_decisions"]; ok && val[0] == "false" {
			c.Log.Debugf("skipping decisions")
		} else {
			alerts = alerts.
				WithDecisions()
		}

		alerts = alerts.
			WithEvents().
			WithMetas().
			WithOwner()

		if limit == 0 {
			limit, err = alerts.Count(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to count nb alerts: %w", err)
			}
		}

		if sort == "ASC" {
			alerts = alerts.Order(ent.Asc(alert.FieldCreatedAt), ent.Asc(alert.FieldID))
		} else {
			alerts = alerts.Order(ent.Desc(alert.FieldCreatedAt), ent.Desc(alert.FieldID))
		}

		result, err := alerts.Limit(paginationSize).Offset(offset).All(ctx)
		if err != nil {
			return nil, errors.Wrapf(QueryFail, "pagination size: %d, offset: %d: %s", paginationSize, offset, err)
		}

		if diff := limit - len(ret); diff < paginationSize {
			if len(result) < diff {
				ret = append(ret, result...)
				c.Log.Debugf("Pagination done, %d < %d", len(result), diff)

				break
			}

			ret = append(ret, result[0:diff]...)
		} else {
			ret = append(ret, result...)
		}

		if len(ret) == limit || len(ret) == 0 || len(ret) < paginationSize {
			c.Log.Debugf("Pagination done len(ret) = %d", len(ret))
			break
		}

		offset += paginationSize
	}

	return ret, nil
}

func (c *Client) DeleteAlertGraphBatch(ctx context.Context, alertItems []*ent.Alert) (int, error) {
	idList := make([]int, 0)
	for _, alert := range alertItems {
		idList = append(idList, alert.ID)
	}

	_, err := c.Ent.Event.Delete().
		Where(event.HasOwnerWith(alert.IDIn(idList...))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraphBatch : %s", err)
		return 0, errors.Wrapf(DeleteFail, "alert graph delete batch events")
	}

	_, err = c.Ent.Meta.Delete().
		Where(meta.HasOwnerWith(alert.IDIn(idList...))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraphBatch : %s", err)
		return 0, errors.Wrapf(DeleteFail, "alert graph delete batch meta")
	}

	_, err = c.Ent.Decision.Delete().
		Where(decision.HasOwnerWith(alert.IDIn(idList...))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraphBatch : %s", err)
		return 0, errors.Wrapf(DeleteFail, "alert graph delete batch decisions")
	}

	deleted, err := c.Ent.Alert.Delete().
		Where(alert.IDIn(idList...)).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraphBatch : %s", err)
		return deleted, errors.Wrapf(DeleteFail, "alert graph delete batch")
	}

	c.Log.Debug("Done batch delete alerts")

	return deleted, nil
}

func (c *Client) DeleteAlertGraph(ctx context.Context, alertItem *ent.Alert) error {
	// delete the associated events
	_, err := c.Ent.Event.Delete().
		Where(event.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "event with alert ID '%d'", alertItem.ID)
	}

	// delete the associated meta
	_, err = c.Ent.Meta.Delete().
		Where(meta.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "meta with alert ID '%d'", alertItem.ID)
	}

	// delete the associated decisions
	_, err = c.Ent.Decision.Delete().
		Where(decision.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "decision with alert ID '%d'", alertItem.ID)
	}

	// delete the alert
	err = c.Ent.Alert.DeleteOne(alertItem).Exec(ctx)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "alert with ID '%d'", alertItem.ID)
	}

	return nil
}

func (c *Client) DeleteAlertByID(ctx context.Context, id int) error {
	alertItem, err := c.Ent.Alert.Query().Where(alert.IDEQ(id)).Only(ctx)
	if err != nil {
		return err
	}

	return c.DeleteAlertGraph(ctx, alertItem)
}

func (c *Client) DeleteAlertWithFilter(ctx context.Context, filter map[string][]string) (int, error) {
	preds, err := AlertPredicatesFromFilter(filter)
	if err != nil {
		return 0, err
	}

	return c.Ent.Alert.Delete().Where(preds...).Exec(ctx)
}

func (c *Client) GetAlertByID(ctx context.Context, alertID int) (*ent.Alert, error) {
	alert, err := c.Ent.Alert.Query().Where(alert.IDEQ(alertID)).WithDecisions().WithEvents().WithMetas().WithOwner().First(ctx)
	if err != nil {
		/*record not found, 404*/
		if ent.IsNotFound(err) {
			log.Warningf("GetAlertByID (not found): %s", err)
			return &ent.Alert{}, ItemNotFound
		}

		c.Log.Warningf("GetAlertByID : %s", err)

		return &ent.Alert{}, QueryFail
	}

	return alert, nil
}
