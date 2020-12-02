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
	paginationSize = 100 // used to queryAlert to avoid 'too many SQL variable'
	defaultLimit   = 100 // default limit of element to returns when query alerts
	bulkSize       = 50  // bulk size when create alerts
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

func (c *Client) CreateAlertBulk(machineId string, alertList []*models.Alert) ([]string, error) {

	ret := []string{}
	bulkSize := 20

	c.Log.Debugf("writting %d items", len(alertList))
	bulk := make([]*ent.AlertCreate, 0, bulkSize)
	for i, alertItem := range alertList {
		var decisions []*ent.Decision
		var metas []*ent.Meta
		var events []*ent.Event

		owner, err := c.QueryMachineByID(machineId)
		if err != nil {
			if errors.Cause(err) != UserNotExists {
				return []string{}, errors.Wrapf(QueryFail, "machine '%s': %s", alertItem.MachineID, err)
			}
			log.Debugf("CreateAlertBulk: Machine Id %s doesn't exist", machineId)
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
			log.Info(disp)
		}

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

				eventBulk[i] = c.Ent.Event.Create().
					SetTime(ts).
					SetSerialized(string(marshallMetas))
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
			log.Errorf("While parsing StartAt of item %s : %s", *alertItem.StopAt, err)
			ts = time.Now()
		}
		if len(alertItem.Decisions) > 0 {
			decisionBulk := make([]*ent.DecisionCreate, len(alertItem.Decisions))
			for i, decisionItem := range alertItem.Decisions {

				duration, err := time.ParseDuration(*decisionItem.Duration)
				if err != nil {
					return []string{}, errors.Wrapf(ParseDurationFail, "decision duration '%v' : %s", decisionItem.Duration, err)
				}
				decisionBulk[i] = c.Ent.Decision.Create().
					SetUntil(ts.Add(duration)).
					SetScenario(*decisionItem.Scenario).
					SetType(*decisionItem.Type).
					SetStartIP(decisionItem.StartIP).
					SetEndIP(decisionItem.EndIP).
					SetValue(*decisionItem.Value).
					SetScope(*decisionItem.Scope).
					SetOrigin(*decisionItem.Origin).
					SetSimulated(*alertItem.Simulated)
			}
			decisions, err = c.Ent.Decision.CreateBulk(decisionBulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "creating alert decisions: %s", err)

			}
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
			AddDecisions(decisions...).
			AddEvents(events...).
			AddMetas(metas...)

		if owner != nil {
			alertB.SetOwner(owner)
		}
		bulk = append(bulk, alertB)

		if len(bulk) == bulkSize {
			alerts, err := c.Ent.Alert.CreateBulk(bulk...).Save(c.CTX)
			if err != nil {
				return []string{}, errors.Wrapf(BulkError, "bulk creating alert : %s", err)
			}
			for _, alert := range alerts {
				ret = append(ret, strconv.Itoa(alert.ID))
			}

			if len(alertList)-i <= bulkSize {
				bulk = make([]*ent.AlertCreate, 0, (len(alertList) - i))
			} else {
				bulk = make([]*ent.AlertCreate, 0, bulkSize)
			}
		}
	}

	alerts, err := c.Ent.Alert.CreateBulk(bulk...).Save(c.CTX)
	if err != nil {
		return []string{}, errors.Wrapf(BulkError, "leftovers creating alert : %s", err)
	}

	for _, alert := range alerts {
		ret = append(ret, strconv.Itoa(alert.ID))
	}

	return ret, nil
}

func BuildAlertRequestFromFilter(alerts *ent.AlertQuery, filter map[string][]string) (*ent.AlertQuery, error) {
	var err error
	var startIP, endIP int64
	var hasActiveDecision bool

	/*the simulated filter is a bit different : if it's not present *or* set to false, specifically exclude records with simulated to true */
	if v, ok := filter["simulated"]; ok {
		if v[0] == "false" {
			alerts = alerts.Where(alert.SimulatedEQ(false))
		}
		delete(filter, "simulated")
	}

	for param, value := range filter {
		switch param {
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
			alerts = alerts.Where(alert.ScenarioEQ(value[0]))
		case "ip":
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to parse '%s': %s", value[0], err)
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
			if err != nil {
				return nil, errors.Wrapf(InvalidIPOrRange, "unable to convert '%s' to int interval: %s", value[0], err)
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
		case "include_capi": //allows to exclude one or more specific origins
			if value[0] == "false" {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.OriginNEQ("CAPI")))
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
	if startIP != 0 && endIP != 0 {
		/*the user is checking for a single IP*/
		if startIP == endIP {
			//DECISION_START <= IP_Q >= DECISON_END
			alerts = alerts.Where(alert.And(
				alert.HasDecisionsWith(decision.StartIPLTE(startIP)),
				alert.HasDecisionsWith(decision.EndIPGTE(endIP)),
			))
		} else { /*the user is checking for a RANGE */
			//START_Q >= DECISION_START AND END_Q <= DECISION_END
			alerts = alerts.Where(alert.And(
				alert.HasDecisionsWith(decision.StartIPGTE(startIP)),
				alert.HasDecisionsWith(decision.EndIPLTE(endIP)),
			))
		}
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
			log.Errorf("invalid 'sort' parameter: %s", val)
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
		if sort == "ASC" {
			alerts = alerts.Order(ent.Asc(alert.FieldCreatedAt))
		} else {
			alerts = alerts.Order(ent.Desc(alert.FieldCreatedAt))
		}
		if limit == 0 {
			limit, err = alerts.Count(c.CTX)
			if err != nil {
				return []*ent.Alert{}, fmt.Errorf("unable to count nb alerts: %s", err)
			}
		}
		result, err := alerts.Limit(paginationSize).Offset(offset).All(c.CTX)
		if err != nil {
			return []*ent.Alert{}, errors.Wrapf(QueryFail, "pagination size: %d, offset: %d: %s", paginationSize, offset, err)
		}
		if diff := limit - len(ret); diff < paginationSize {
			if len(result) < diff {
				ret = append(ret, result...)
				log.Debugf("Pagination done, %d < %d", len(result), diff)
				break
			}
			ret = append(ret, result[0:diff]...)
		} else {
			ret = append(ret, result...)
		}
		if len(ret) == limit || len(ret) == 0 {
			log.Debugf("Pagination done len(ret) = %d", len(ret))
			break
		}
		offset += paginationSize
	}

	return ret, nil
}

func (c *Client) DeleteAlertGraph(alertItem *ent.Alert) error {
	// delete the associated events
	_, err := c.Ent.Event.Delete().
		Where(event.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "event with alert ID '%d'", alertItem.ID)
	}

	// delete the associated meta
	_, err = c.Ent.Meta.Delete().
		Where(meta.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "meta with alert ID '%d'", alertItem.ID)
	}

	// delete the associated decisions
	_, err = c.Ent.Decision.Delete().
		Where(decision.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteAlertGraph : %s", err)
		return errors.Wrapf(DeleteFail, "decision with alert ID '%d'", alertItem.ID)
	}

	// delete the alert
	err = c.Ent.Alert.DeleteOne(alertItem).Exec(c.CTX)
	if err != nil {
		log.Warningf("DeleteAlertGraph : %s", err)
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
			log.Warningf("DeleteAlertWithFilter : %s", err)
			return 0, errors.Wrapf(DeleteFail, "event with alert ID '%d'", alertItem.ID)
		}
	}
	return len(alertsToDelete), nil
}

func (c *Client) FlushAlerts(MaxAge string, MaxItems int) error {
	var deletedByAge int
	var deletedByNbItem int
	var totalAlerts int
	var err error
	totalAlerts, err = c.TotalAlerts()
	if err != nil {
		log.Warningf("FlushAlerts (max items count) : %s", err)
		return errors.Wrap(err, "unable to get alerts count")
	}
	if MaxAge != "" {
		filter := map[string][]string{
			"created_before": {MaxAge},
		}
		nbDeleted, err := c.DeleteAlertWithFilter(filter)
		if err != nil {
			log.Warningf("FlushAlerts (max age) : %s", err)
			return errors.Wrapf(err, "unable to flush alerts with filter until: %s", MaxAge)
		}
		deletedByAge = nbDeleted
	}
	if MaxItems > 0 {
		if totalAlerts > MaxItems {
			nbToDelete := totalAlerts - MaxItems
			alerts, err := c.QueryAlertWithFilter(map[string][]string{
				"sort":  {"ASC"},
				"limit": {strconv.Itoa(nbToDelete)},
			}) // we want to delete older alerts if we reach the max number of items
			if err != nil {
				log.Warningf("FlushAlerts (max items query) : %s", err)
				return errors.Wrap(err, "unable to get all alerts")
			}
			for itemNb, alert := range alerts {
				if itemNb < nbToDelete {
					err := c.DeleteAlertGraph(alert)
					if err != nil {
						log.Warningf("FlushAlerts : %s", err)
						return errors.Wrap(err, "unable to flush alert")
					}
					deletedByNbItem++
				}
			}
		}
	}
	if deletedByNbItem > 0 {
		log.Infof("flushed %d/%d alerts because max number of alerts has been reached (%d max)", deletedByNbItem, totalAlerts, MaxItems)
	}
	if deletedByAge > 0 {
		log.Infof("flushed %d/%d alerts because they were created %s ago or more", deletedByAge, totalAlerts, MaxAge)
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
		log.Warningf("GetAlertByID : %s", err)
		return &ent.Alert{}, QueryFail
	}
	return alert, nil
}
