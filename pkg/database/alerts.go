package database

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	paginationSize   = 100 // used to queryAlert to avoid 'too many SQL variable'
	defaultLimit     = 100 // default limit of element to returns when query alerts
	bulkSize         = 50  // bulk size when create alerts
	decisionBulkSize = 50
)

func formatAlertAsString(machineId string, alert *models.Alert) []string {
	var retStr []string

	/**/
	src := ""
	if alert.Source != nil {
		if *alert.Source.Scope == types.Ip {
			src = fmt.Sprintf("ip %s", *alert.Source.Value)
			if alert.Source.Cn != "" {
				src += " (" + alert.Source.Cn
				if alert.Source.AsNumber != "" {
					src += "/" + alert.Source.AsNumber
				}
				src += ")"
			}
		} else if *alert.Source.Scope == types.Range {
			src = fmt.Sprintf("range %s", *alert.Source.Value)
			if alert.Source.Cn != "" {
				src += " (" + alert.Source.Cn
				if alert.Source.AsNumber != "" {
					src += "/" + alert.Source.AsNumber
				}
				src += ")"
			}
		} else {
			src = fmt.Sprintf("%s %s", *alert.Source.Scope, *alert.Source.Value)
		}
	} else {
		src = "empty source"
	}

	/**/
	reason := ""
	if *alert.Scenario != "" {
		reason = fmt.Sprintf("%s by %s", *alert.Scenario, src)
	} else if *alert.Message != "" {
		reason = fmt.Sprintf("%s by %s", *alert.Scenario, src)
	} else {
		reason = fmt.Sprintf("empty scenario by %s", src)
	}

	if len(alert.Decisions) > 0 {
		for _, decisionItem := range alert.Decisions {
			decision := ""
			if alert.Simulated != nil && *alert.Simulated {
				decision = "(simulated alert)"
			} else if decisionItem.Simulated != nil && *decisionItem.Simulated {
				decision = "(simulated decision)"
			}
			if log.GetLevel() >= log.DebugLevel {
				/*spew is expensive*/
				log.Debugf("%s", spew.Sdump(decisionItem))
			}
			decision += fmt.Sprintf("%s %s on %s %s", *decisionItem.Duration,
				*decisionItem.Type, *decisionItem.Scope, *decisionItem.Value)
			retStr = append(retStr,
				fmt.Sprintf("(%s/%s) %s : %s", machineId,
					*decisionItem.Origin, reason, decision))
		}
	} else {
		retStr = append(retStr, fmt.Sprintf("(%s) alert : %s", machineId, reason))
	}
	return retStr
}

func (c *Client) CreateAlert(machineID string, alertList []*models.Alert) ([]string, error) {
	pageStart := 0
	pageEnd := bulkSize
	ret := []string{}
	for {
		if pageEnd >= len(alertList) {
			results, err := c.CreateAlertBulk(machineID, alertList[pageStart:])
			if err != nil {
				return []string{}, fmt.Errorf("unable to create alerts: %s", err)
			}
			ret = append(ret, results...)
			break
		}
		results, err := c.CreateAlertBulk(machineID, alertList[pageStart:pageEnd])
		if err != nil {
			return []string{}, fmt.Errorf("unable to create alerts: %s", err)
		}
		ret = append(ret, results...)
		pageStart += bulkSize
		pageEnd += bulkSize
	}
	return ret, nil
}

/*We can't bulk both the alert and the decision at the same time. With new consensus, we want to bulk a single alert with a lot of decisions.*/
func (c *Client) UpdateCommunityBlocklist(alertItem *models.Alert) (int, int, int, error) {

	var err error
	var deleted, inserted int

	if alertItem == nil {
		return 0, 0, 0, fmt.Errorf("nil alert")
	}
	if alertItem.StartAt == nil {
		return 0, 0, 0, fmt.Errorf("nil start_at")
	}
	startAtTime, err := time.Parse(time.RFC3339, *alertItem.StartAt)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(ParseTimeFail, "start_at field time '%s': %s", *alertItem.StartAt, err)
	}
	if alertItem.StopAt == nil {
		return 0, 0, 0, fmt.Errorf("nil stop_at")
	}
	stopAtTime, err := time.Parse(time.RFC3339, *alertItem.StopAt)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(ParseTimeFail, "stop_at field time '%s': %s", *alertItem.StopAt, err)
	}

	ts, err := time.Parse(time.RFC3339, *alertItem.StopAt)
	if err != nil {
		c.Log.Errorf("While parsing StartAt of item %s : %s", *alertItem.StopAt, err)
		ts = time.Now()
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
		SetScenarioHash(*alertItem.ScenarioHash)

	alertRef, err := alertB.Save(c.CTX)
	if err != nil {
		return 0, 0, 0, errors.Wrapf(BulkError, "error creating alert : %s", err)
	}

	if len(alertItem.Decisions) > 0 {
		decisionBulk := make([]*ent.DecisionCreate, 0, decisionBulkSize)
		valueList := make([]string, 0, decisionBulkSize)
		for i, decisionItem := range alertItem.Decisions {
			var start_ip, start_sfx, end_ip, end_sfx int64
			var sz int
			if decisionItem.Duration == nil {
				log.Warningf("nil duration in community decision")
				continue
			}
			duration, err := time.ParseDuration(*decisionItem.Duration)
			if err != nil {
				return 0, 0, 0, errors.Wrapf(ParseDurationFail, "decision duration '%v' : %s", decisionItem.Duration, err)
			}
			if decisionItem.Scope == nil {
				log.Warningf("nil scope in community decision")
				continue
			}
			/*if the scope is IP or Range, convert the value to integers */
			if strings.ToLower(*decisionItem.Scope) == "ip" || strings.ToLower(*decisionItem.Scope) == "range" {
				sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(*decisionItem.Value)
				if err != nil {
					return 0, 0, 0, errors.Wrapf(ParseDurationFail, "invalid addr/range %s : %s", *decisionItem.Value, err)
				}
			}
			/*bulk insert some new decisions*/
			decisionBulk = append(decisionBulk, c.Ent.Decision.Create().
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
				SetOwner(alertRef))

			/*for bulk delete of duplicate decisions*/
			if decisionItem.Value == nil {
				log.Warningf("nil value in community decision")
				continue
			}
			valueList = append(valueList, *decisionItem.Value)

			if len(decisionBulk) == decisionBulkSize {
				insertedDecisions, err := c.Ent.Decision.CreateBulk(decisionBulk...).Save(c.CTX)
				if err != nil {
					return 0, 0, 0, errors.Wrapf(BulkError, "bulk creating decisions : %s", err)
				}
				inserted += len(insertedDecisions)

				/*Deleting older decisions from capi*/
				deletedDecisions, err := c.Ent.Decision.Delete().
					Where(decision.And(
						decision.OriginEQ(CapiMachineID),
						decision.Not(decision.HasOwnerWith(alert.IDEQ(alertRef.ID))),
						decision.ValueIn(valueList...),
					)).Exec(c.CTX)
				if err != nil {
					return 0, 0, 0, errors.Wrap(err, "while deleting older community blocklist decisions")
				}
				deleted += deletedDecisions

				if len(alertItem.Decisions)-i <= decisionBulkSize {
					decisionBulk = make([]*ent.DecisionCreate, 0, (len(alertItem.Decisions) - i))
					valueList = make([]string, 0, (len(alertItem.Decisions) - i))
				} else {
					decisionBulk = make([]*ent.DecisionCreate, 0, decisionBulkSize)
					valueList = make([]string, 0, decisionBulkSize)
				}

				// The 90's called, they want their concurrency back.
				// This is needed for sqlite, which does not support concurrent access while writing.
				// If we pull a large number of IPs from CAPI, and we have a slow disk, LAPI won't respond until all IPs are inserted (which can take up to a few seconds).
				time.Sleep(100 * time.Millisecond)
			}

		}
		insertedDecisions, err := c.Ent.Decision.CreateBulk(decisionBulk...).Save(c.CTX)
		if err != nil {
			return 0, 0, 0, errors.Wrapf(BulkError, "creating alert decisions: %s", err)
		}
		inserted += len(insertedDecisions)
		/*Deleting older decisions from capi*/
		if len(valueList) > 0 {
			deletedDecisions, err := c.Ent.Decision.Delete().
				Where(decision.And(
					decision.OriginEQ(CapiMachineID),
					decision.Not(decision.HasOwnerWith(alert.IDEQ(alertRef.ID))),
					decision.ValueIn(valueList...),
				)).Exec(c.CTX)
			if err != nil {
				return 0, 0, 0, errors.Wrap(err, "while deleting older community blocklist decisions")
			}
			deleted += deletedDecisions
		}

	}

	return alertRef.ID, inserted, deleted, nil
}

func chunkDecisions(decisions []*ent.Decision, chunkSize int) [][]*ent.Decision {
	var ret [][]*ent.Decision
	var chunk []*ent.Decision

	for _, d := range decisions {
		chunk = append(chunk, d)
		if len(chunk) == chunkSize {
			ret = append(ret, chunk)
			chunk = nil
		}
	}
	if len(chunk) > 0 {
		ret = append(ret, chunk)
	}
	return ret
}

func (c *Client) CreateAlertBulk(machineId string, alertList []*models.Alert) ([]string, error) {
	ret := []string{}
	bulkSize := 20

	c.Log.Debugf("writting %d items", len(alertList))
	bulk := make([]*ent.AlertCreate, 0, bulkSize)
	alertDecisions := make([][]*ent.Decision, 0, bulkSize)
	for i, alertItem := range alertList {
		var decisions []*ent.Decision
		var metas []*ent.Meta
		var events []*ent.Event

		owner, err := c.QueryMachineByID(machineId)
		if err != nil {
			if errors.Cause(err) != UserNotExists {
				return []string{}, errors.Wrapf(QueryFail, "machine '%s': %s", alertItem.MachineID, err)
			}
			c.Log.Debugf("CreateAlertBulk: Machine Id %s doesn't exist", machineId)
			owner = nil
		}
		startAtTime, err := time.Parse(time.RFC3339, *alertItem.StartAt)
		if err != nil {
			return []string{}, errors.Wrapf(ParseTimeFail, "start_at field time '%s': %s", *alertItem.StartAt, err)
		}

		stopAtTime, err := time.Parse(time.RFC3339, *alertItem.StopAt)
		if err != nil {
			return []string{}, errors.Wrapf(ParseTimeFail, "stop_at field time '%s': %s", *alertItem.StopAt, err)
		}
		/*display proper alert in logs*/
		for _, disp := range formatAlertAsString(machineId, alertItem) {
			c.Log.Info(disp)
		}

		//let's track when we strip or drop data, notify outside of loop to avoid spam
		stripped := false
		dropped := false

		if len(alertItem.Events) > 0 {
			eventBulk := make([]*ent.EventCreate, len(alertItem.Events))
			for i, eventItem := range alertItem.Events {
				ts, err := time.Parse(time.RFC3339, *eventItem.Timestamp)
				if err != nil {
					return []string{}, errors.Wrapf(ParseTimeFail, "event timestamp '%s' : %s", *eventItem.Timestamp, err)
				}
				marshallMetas, err := json.Marshal(eventItem.Meta)
				if err != nil {
					return []string{}, errors.Wrapf(MarshalFail, "event meta '%v' : %s", eventItem.Meta, err)
				}

				//the serialized field is too big, let's try to progressively strip it
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
							return []string{}, errors.Wrapf(MarshalFail, "event meta '%v' : %s", eventItem.Meta, err)
						}
						if event.SerializedValidator(string(marshallMetas)) == nil {
							valid = true
						}
						stripSize /= 2
					}

					//nothing worked, drop it
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
				c.Log.Warningf("stripped 'serialized' field (machine %s / scenario %s)", machineId, *alertItem.Scenario)
			}
			if dropped {
				c.Log.Warningf("dropped 'serialized' field (machine %s / scenario %s)", machineId, *alertItem.Scenario)
			}
			events, err = c.Ent.Event.CreateBulk(eventBulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "creating alert events: %s", err)
			}
		}

		if len(alertItem.Meta) > 0 {
			metaBulk := make([]*ent.MetaCreate, len(alertItem.Meta))
			for i, metaItem := range alertItem.Meta {
				metaBulk[i] = c.Ent.Meta.Create().
					SetKey(metaItem.Key).
					SetValue(metaItem.Value)
			}
			metas, err = c.Ent.Meta.CreateBulk(metaBulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "creating alert meta: %s", err)
			}
		}

		ts, err := time.Parse(time.RFC3339, *alertItem.StopAt)
		if err != nil {
			c.Log.Errorf("While parsing StartAt of item %s : %s", *alertItem.StopAt, err)
			ts = time.Now()
		}

		decisions = make([]*ent.Decision, 0)
		if len(alertItem.Decisions) > 0 {
			decisionBulk := make([]*ent.DecisionCreate, 0, decisionBulkSize)
			for i, decisionItem := range alertItem.Decisions {
				var start_ip, start_sfx, end_ip, end_sfx int64
				var sz int

				duration, err := time.ParseDuration(*decisionItem.Duration)
				if err != nil {
					return []string{}, errors.Wrapf(ParseDurationFail, "decision duration '%v' : %s", decisionItem.Duration, err)
				}

				/*if the scope is IP or Range, convert the value to integers */
				if strings.ToLower(*decisionItem.Scope) == "ip" || strings.ToLower(*decisionItem.Scope) == "range" {
					sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(*decisionItem.Value)
					if err != nil {
						return []string{}, errors.Wrapf(ParseDurationFail, "invalid addr/range %s : %s", *decisionItem.Value, err)
					}
				}

				decisionCreate := c.Ent.Decision.Create().
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
					SetSimulated(*alertItem.Simulated)

				decisionBulk = append(decisionBulk, decisionCreate)
				if len(decisionBulk) == decisionBulkSize {
					decisionsCreateRet, err := c.Ent.Decision.CreateBulk(decisionBulk...).Save(c.CTX)
					if err != nil {
						return []string{}, errors.Wrapf(BulkError, "creating alert decisions: %s", err)

					}
					decisions = append(decisions, decisionsCreateRet...)
					if len(alertItem.Decisions)-i <= decisionBulkSize {
						decisionBulk = make([]*ent.DecisionCreate, 0, (len(alertItem.Decisions) - i))
					} else {
						decisionBulk = make([]*ent.DecisionCreate, 0, decisionBulkSize)
					}
				}
			}
			decisionsCreateRet, err := c.Ent.Decision.CreateBulk(decisionBulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "creating alert decisions: %s", err)
			}
			decisions = append(decisions, decisionsCreateRet...)
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
			AddEvents(events...).
			AddMetas(metas...)

		if owner != nil {
			alertB.SetOwner(owner)
		}
		bulk = append(bulk, alertB)
		alertDecisions = append(alertDecisions, decisions)

		if len(bulk) == bulkSize {
			alerts, err := c.Ent.Alert.CreateBulk(bulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "bulk creating alert : %s", err)
			}
			for alertIndex, a := range alerts {
				ret = append(ret, strconv.Itoa(a.ID))
				d := alertDecisions[alertIndex]
				decisionsChunk := chunkDecisions(d, bulkSize)
				for _, d2 := range decisionsChunk {
					_, err := c.Ent.Alert.Update().Where(alert.IDEQ(a.ID)).AddDecisions(d2...).Save(c.CTX)
					if err != nil {
						return []string{}, fmt.Errorf("error while updating decisions: %s", err.Error())
					}
				}
			}
			if len(alertList)-i <= bulkSize {
				bulk = make([]*ent.AlertCreate, 0, (len(alertList) - i))
				alertDecisions = make([][]*ent.Decision, 0, (len(alertList) - i))
			} else {
				bulk = make([]*ent.AlertCreate, 0, bulkSize)
				alertDecisions = make([][]*ent.Decision, 0, bulkSize)
			}
		}
	}

	alerts, err := c.Ent.Alert.CreateBulk(bulk...).Save(c.CTX)
	if err != nil {
		return []string{}, errors.Wrapf(BulkError, "leftovers creating alert : %s", err)
	}

	for alertIndex, a := range alerts {
		ret = append(ret, strconv.Itoa(a.ID))
		d := alertDecisions[alertIndex]
		decisionsChunk := chunkDecisions(d, bulkSize)
		for _, d2 := range decisionsChunk {
			_, err := c.Ent.Alert.Update().Where(alert.IDEQ(a.ID)).AddDecisions(d2...).Save(c.CTX)
			if err != nil {
				return []string{}, fmt.Errorf("error while updating decisions: %s", err.Error())
			}
		}
	}

	return ret, nil
}

func BuildAlertRequestFromFilter(alerts *ent.AlertQuery, filter map[string][]string) (*ent.AlertQuery, error) {
	var err error
	var start_ip, start_sfx, end_ip, end_sfx int64
	var hasActiveDecision bool
	var ip_sz int
	var contains bool = true
	/*if contains is true, return bans that *contains* the given value (value is the inner)
	  else, return bans that are *contained* by the given value (value is the outer)*/

	/*the simulated filter is a bit different : if it's not present *or* set to false, specifically exclude records with simulated to true */
	if v, ok := filter["simulated"]; ok {
		if v[0] == "false" {
			alerts = alerts.Where(alert.SimulatedEQ(false))
		}
		delete(filter, "simulated")
	}

	if _, ok := filter["origin"]; ok {
		filter["include_capi"] = []string{"true"}
	}

	for param, value := range filter {
		switch param {
		case "contains":
			contains, err = strconv.ParseBool(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidFilter, "invalid contains value : %s", err)
			}
		case "scope":
			var scope string = value[0]
			if strings.ToLower(scope) == "ip" {
				scope = types.Ip
			} else if strings.ToLower(scope) == "range" {
				scope = types.Range
			}
			alerts = alerts.Where(alert.SourceScopeEQ(scope))
		case "value":
			alerts = alerts.Where(alert.SourceValueEQ(value[0]))
		case "scenario":
			alerts = alerts.Where(alert.HasDecisionsWith(decision.ScenarioEQ(value[0])))
		case "ip", "range":
			ip_sz, start_ip, start_sfx, end_ip, end_sfx, err = types.Addr2Ints(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int: %s", value[0], err)
			}
		case "since":
			duration, err := types.ParseDuration(value[0])
			if err != nil {
				return nil, errors.Wrap(err, "while parsing duration")
			}
			since := time.Now().Add(-duration)
			if since.IsZero() {
				return nil, fmt.Errorf("Empty time now() - %s", since.String())
			}
			alerts = alerts.Where(alert.StartedAtGTE(since))
		case "created_before":
			duration, err := types.ParseDuration(value[0])
			if err != nil {
				return nil, errors.Wrap(err, "while parsing duration")
			}
			since := time.Now().Add(-duration)
			if since.IsZero() {
				return nil, fmt.Errorf("Empty time now() - %s", since.String())
			}
			alerts = alerts.Where(alert.CreatedAtLTE(since))
		case "until":
			duration, err := types.ParseDuration(value[0])
			if err != nil {
				return nil, errors.Wrap(err, "while parsing duration")
			}
			until := time.Now().Add(-duration)
			if until.IsZero() {
				return nil, fmt.Errorf("Empty time now() - %s", until.String())
			}
			alerts = alerts.Where(alert.StartedAtLTE(until))
		case "decision_type":
			alerts = alerts.Where(alert.HasDecisionsWith(decision.TypeEQ(value[0])))
		case "origin":
			alerts = alerts.Where(alert.HasDecisionsWith(decision.OriginEQ(value[0])))
		case "include_capi": //allows to exclude one or more specific origins
			if value[0] == "false" {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.Or(decision.OriginEQ("crowdsec"), decision.OriginEQ("cscli"))))
			} else if value[0] != "true" {
				log.Errorf("Invalid bool '%s' for include_capi", value[0])
			}
		case "has_active_decision":
			if hasActiveDecision, err = strconv.ParseBool(value[0]); err != nil {
				return nil, errors.Wrapf(ParseType, "'%s' is not a boolean: %s", value[0], err)
			}
			if hasActiveDecision {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.UntilGTE(time.Now())))
			} else {
				alerts = alerts.Where(alert.Not(alert.HasDecisions()))
			}
		case "limit":
			continue
		case "sort":
			continue
		default:
			return nil, errors.Wrapf(InvalidFilter, "Filter parameter '%s' is unknown (=%s)", param, value[0])
		}
	}

	if ip_sz == 4 {
		if contains { /*decision contains {start_ip,end_ip}*/
			alerts = alerts.Where(alert.And(
				alert.HasDecisionsWith(decision.StartIPLTE(start_ip)),
				alert.HasDecisionsWith(decision.EndIPGTE(end_ip)),
				alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			))
		} else { /*decision is contained within {start_ip,end_ip}*/
			alerts = alerts.Where(alert.And(
				alert.HasDecisionsWith(decision.StartIPGTE(start_ip)),
				alert.HasDecisionsWith(decision.EndIPLTE(end_ip)),
				alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
			))
		}
	} else if ip_sz == 16 {

		if contains { /*decision contains {start_ip,end_ip}*/
			alerts = alerts.Where(alert.And(
				//matching addr size
				alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
				alert.Or(
					//decision.start_ip < query.start_ip
					alert.HasDecisionsWith(decision.StartIPLT(start_ip)),
					alert.And(
						//decision.start_ip == query.start_ip
						alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
						//decision.start_suffix <= query.start_suffix
						alert.HasDecisionsWith(decision.StartSuffixLTE(start_sfx)),
					)),
				alert.Or(
					//decision.end_ip > query.end_ip
					alert.HasDecisionsWith(decision.EndIPGT(end_ip)),
					alert.And(
						//decision.end_ip == query.end_ip
						alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
						//decision.end_suffix >= query.end_suffix
						alert.HasDecisionsWith(decision.EndSuffixGTE(end_sfx)),
					),
				),
			))
		} else { /*decision is contained within {start_ip,end_ip}*/
			alerts = alerts.Where(alert.And(
				//matching addr size
				alert.HasDecisionsWith(decision.IPSizeEQ(int64(ip_sz))),
				alert.Or(
					//decision.start_ip > query.start_ip
					alert.HasDecisionsWith(decision.StartIPGT(start_ip)),
					alert.And(
						//decision.start_ip == query.start_ip
						alert.HasDecisionsWith(decision.StartIPEQ(start_ip)),
						//decision.start_suffix >= query.start_suffix
						alert.HasDecisionsWith(decision.StartSuffixGTE(start_sfx)),
					)),
				alert.Or(
					//decision.end_ip < query.end_ip
					alert.HasDecisionsWith(decision.EndIPLT(end_ip)),
					alert.And(
						//decision.end_ip == query.end_ip
						alert.HasDecisionsWith(decision.EndIPEQ(end_ip)),
						//decision.end_suffix <= query.end_suffix
						alert.HasDecisionsWith(decision.EndSuffixLTE(end_sfx)),
					),
				),
			))
		}
	} else if ip_sz != 0 {
		return nil, errors.Wrapf(InvalidFilter, "Unknown ip size %d", ip_sz)
	}
	return alerts, nil
}

func (c *Client) TotalAlerts() (int, error) {
	return c.Ent.Alert.Query().Count(c.CTX)
}

func (c *Client) QueryAlertWithFilter(filter map[string][]string) ([]*ent.Alert, error) {
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
			return []*ent.Alert{}, errors.Wrapf(QueryFail, "bad limit in parameters: %s", val)
		}
		limit = limitConv

	}
	offset := 0
	ret := make([]*ent.Alert, 0)
	for {
		alerts := c.Ent.Alert.Query()
		alerts, err := BuildAlertRequestFromFilter(alerts, filter)
		if err != nil {
			return []*ent.Alert{}, err
		}
		alerts = alerts.
			WithDecisions().
			WithEvents().
			WithMetas().
			WithOwner()

		if limit == 0 {
			limit, err = alerts.Count(c.CTX)
			if err != nil {
				return []*ent.Alert{}, fmt.Errorf("unable to count nb alerts: %s", err)
			}
		}

		if sort == "ASC" {
			alerts = alerts.Order(ent.Asc(alert.FieldCreatedAt))
		} else {
			alerts = alerts.Order(ent.Desc(alert.FieldCreatedAt))
		}

		result, err := alerts.Limit(paginationSize).Offset(offset).All(c.CTX)
		if err != nil {
			return []*ent.Alert{}, errors.Wrapf(QueryFail, "pagination size: %d, offset: %d: %s", paginationSize, offset, err)
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
		if len(ret) == limit || len(ret) == 0 {
			c.Log.Debugf("Pagination done len(ret) = %d", len(ret))
			break
		}
		offset += paginationSize
	}

	return ret, nil
}

func (c *Client) DeleteAlertGraphBatch(alertItems []*ent.Alert) (int, error) {
	idList := make([]int, 0)
	for _, alert := range alertItems {
		idList = append(idList, int(alert.ID))
	}

	deleted, err := c.Ent.Alert.Delete().
		Where(alert.IDIn(idList...)).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return deleted, errors.Wrapf(DeleteFail, "alert graph delete batch")
	}

	c.Log.Debug("Done batch delete alerts")

	return deleted, nil
}

func (c *Client) DeleteAlertGraph(alertItem *ent.Alert) error {
	// delete the associated events
	_, err := c.Ent.Event.Delete().
		Where(event.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "event with alert ID '%d'", alertItem.ID)
	}

	// delete the associated meta
	_, err = c.Ent.Meta.Delete().
		Where(meta.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "meta with alert ID '%d'", alertItem.ID)
	}

	// delete the associated decisions
	_, err = c.Ent.Decision.Delete().
		Where(decision.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "decision with alert ID '%d'", alertItem.ID)
	}

	// delete the alert
	err = c.Ent.Alert.DeleteOne(alertItem).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "alert with ID '%d'", alertItem.ID)
	}

	return nil
}

func (c *Client) DeleteAlertWithFilter(filter map[string][]string) (int, error) {
	var err error

	// Get all the alerts that match the filter
	alertsToDelete, err := c.QueryAlertWithFilter(filter)

	for _, alertItem := range alertsToDelete {
		err = c.DeleteAlertGraph(alertItem)
		if err != nil {
			c.Log.Warningf("DeleteAlertWithFilter : %s", err)
			return 0, errors.Wrapf(DeleteFail, "event with alert ID '%d'", alertItem.ID)
		}
	}
	return len(alertsToDelete), nil
}

func (c *Client) FlushOrphans() {
	/* While it has only been linked to some very corner-case bug : https://github.com/crowdsecurity/crowdsec/issues/778 */
	/* We want to take care of orphaned events for which the parent alert/decision has been deleted */

	events_count, err := c.Ent.Event.Delete().Where(event.Not(event.HasOwner())).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("error while deleting orphan events : %s", err)
		return
	}
	if events_count > 0 {
		c.Log.Infof("%d deleted orphan events", events_count)
	}

	events_count, err = c.Ent.Decision.Delete().Where(
		decision.Not(decision.HasOwner())).Where(decision.UntilLTE(time.Now())).Exec(c.CTX)

	if err != nil {
		c.Log.Warningf("error while deleting orphan decisions : %s", err)
		return
	}
	if events_count > 0 {
		c.Log.Infof("%d deleted orphan decisions", events_count)
	}
}

func (c *Client) FlushAlerts(MaxAge string, MaxItems int) error {
	var deletedByAge int
	var deletedByNbItem int
	var totalAlerts int
	var err error

	if !c.CanFlush {
		c.Log.Debug("a list is being imported, flushing later")
		return nil
	}

	c.Log.Debug("Flushing orphan alerts")
	c.FlushOrphans()
	c.Log.Debug("Done flushing orphan alerts")
	totalAlerts, err = c.TotalAlerts()
	if err != nil {
		c.Log.Warningf("FlushAlerts (max items count) : %s", err)
		return errors.Wrap(err, "unable to get alerts count")
	}
	c.Log.Debugf("FlushAlerts (Total alerts): %d", totalAlerts)
	if MaxAge != "" {
		filter := map[string][]string{
			"created_before": {MaxAge},
		}
		nbDeleted, err := c.DeleteAlertWithFilter(filter)
		if err != nil {
			c.Log.Warningf("FlushAlerts (max age) : %s", err)
			return errors.Wrapf(err, "unable to flush alerts with filter until: %s", MaxAge)
		}
		c.Log.Debugf("FlushAlerts (deleted max age alerts): %d", nbDeleted)
		deletedByAge = nbDeleted
	}
	if MaxItems > 0 {
		//We get the highest id for the alerts
		//We substract MaxItems to avoid deleting alerts that are not old enough
		//This gives us the oldest alert that we want to keep
		//We then delete all the alerts with an id lower than this one
		//We can do this because the id is auto-increment, and the database won't reuse the same id twice
		lastAlert, err := c.QueryAlertWithFilter(map[string][]string{
			"sort":  {"DESC"},
			"limit": {"1"},
		})
		c.Log.Debugf("FlushAlerts (last alert): %+v", lastAlert)
		if err != nil {
			c.Log.Errorf("FlushAlerts: could not get last alert: %s", err)
			return errors.Wrap(err, "could not get last alert")
		}

		if len(lastAlert) != 0 {
			maxid := lastAlert[0].ID - MaxItems

			c.Log.Debugf("FlushAlerts (max id): %d", maxid)

			if maxid > 0 {
				//This may lead to orphan alerts (at least on MySQL), but the next time the flush job will run, they will be deleted
				deletedByNbItem, err = c.Ent.Alert.Delete().Where(alert.IDLT(maxid)).Exec(c.CTX)

				if err != nil {
					c.Log.Errorf("FlushAlerts: Could not delete alerts : %s", err)
					return errors.Wrap(err, "could not delete alerts")
				}
			}
		}
	}
	if deletedByNbItem > 0 {
		c.Log.Infof("flushed %d/%d alerts because max number of alerts has been reached (%d max)", deletedByNbItem, totalAlerts, MaxItems)
	}
	if deletedByAge > 0 {
		c.Log.Infof("flushed %d/%d alerts because they were created %s ago or more", deletedByAge, totalAlerts, MaxAge)
	}
	return nil
}

func (c *Client) GetAlertByID(alertID int) (*ent.Alert, error) {
	alert, err := c.Ent.Alert.Query().Where(alert.IDEQ(alertID)).WithDecisions().WithEvents().WithMetas().WithOwner().First(c.CTX)
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
