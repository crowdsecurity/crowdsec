package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/jcuga/golongpoll/client"

	"gopkg.in/tomb.v2"
)

var (
	PullInterval    = time.Hour * 2
	PushInterval    = time.Second * 10
	MetricsInterval = time.Minute * 30
)

var SCOPE_CAPI string = "CAPI"
var SCOPE_CAPI_ALIAS string = "crowdsecurity/community-blocklist" //we don't use "CAPI" directly, to make it less confusing for the user
var SCOPE_LISTS string = "lists"

type apic struct {
	pullInterval       time.Duration
	pushInterval       time.Duration
	metricsInterval    time.Duration
	dbClient           *database.Client
	apiClient          *apiclient.ApiClient
	AlertsAddChan      chan []*models.Alert
	DecisionDeleteChan chan []*models.Decision

	mu            sync.Mutex
	pushTomb      tomb.Tomb
	pullTomb      tomb.Tomb
	metricsTomb   tomb.Tomb
	startup       bool
	credentials   *csconfig.ApiCredentialsCfg
	scenarioList  []string
	consoleConfig *csconfig.ConsoleConfig
}

func (a *apic) FetchScenariosListFromDB() ([]string, error) {
	scenarios := make([]string, 0)
	machines, err := a.dbClient.ListMachines()
	if err != nil {
		return nil, errors.Wrap(err, "while listing machines")
	}
	//merge all scenarios together
	for _, v := range machines {
		machineScenarios := strings.Split(v.Scenarios, ",")
		log.Debugf("%d scenarios for machine %d", len(machineScenarios), v.ID)
		for _, sv := range machineScenarios {
			if !types.InSlice(sv, scenarios) && sv != "" {
				scenarios = append(scenarios, sv)
			}
		}
	}
	log.Debugf("Returning list of scenarios : %+v", scenarios)
	return scenarios, nil
}

func decisionsToApiDecisions(decisions []*models.Decision) models.AddSignalsRequestItemDecisions {
	apiDecisions := models.AddSignalsRequestItemDecisions{}
	for _, decision := range decisions {
		x := &models.AddSignalsRequestItemDecisionsItem{
			Duration: types.StrPtr(*decision.Duration),
			ID:       new(int64),
			Origin:   types.StrPtr(*decision.Origin),
			Scenario: types.StrPtr(*decision.Scenario),
			Scope:    types.StrPtr(*decision.Scope),
			//Simulated: *decision.Simulated,
			Type:  types.StrPtr(*decision.Type),
			Until: decision.Until,
			Value: types.StrPtr(*decision.Value),
			UUID:  decision.UUID,
		}
		*x.ID = decision.ID
		if decision.Simulated != nil {
			x.Simulated = *decision.Simulated
		}
		apiDecisions = append(apiDecisions, x)
	}
	return apiDecisions
}

func alertToSignal(alert *models.Alert, scenarioTrust string) *models.AddSignalsRequestItem {
	return &models.AddSignalsRequestItem{
		Message:         alert.Message,
		Scenario:        alert.Scenario,
		ScenarioHash:    alert.ScenarioHash,
		ScenarioVersion: alert.ScenarioVersion,
		Source: &models.AddSignalsRequestItemSource{
			AsName:    alert.Source.AsName,
			AsNumber:  alert.Source.AsNumber,
			Cn:        alert.Source.Cn,
			IP:        alert.Source.IP,
			Latitude:  alert.Source.Latitude,
			Longitude: alert.Source.Longitude,
			Range:     alert.Source.Range,
			Scope:     alert.Source.Scope,
			Value:     alert.Source.Value,
		},
		StartAt:       alert.StartAt,
		StopAt:        alert.StopAt,
		CreatedAt:     alert.CreatedAt,
		MachineID:     alert.MachineID,
		ScenarioTrust: scenarioTrust,
		Decisions:     decisionsToApiDecisions(alert.Decisions),
		UUID:          alert.UUID,
	}
}

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client, consoleConfig *csconfig.ConsoleConfig) (*apic, error) {
	var err error
	ret := &apic{
		AlertsAddChan:      make(chan []*models.Alert),
		DecisionDeleteChan: make(chan []*models.Decision),
		dbClient:           dbClient,
		mu:                 sync.Mutex{},
		startup:            true,
		credentials:        config.Credentials,
		pullTomb:           tomb.Tomb{},
		pushTomb:           tomb.Tomb{},
		metricsTomb:        tomb.Tomb{},
		scenarioList:       make([]string, 0),
		consoleConfig:      consoleConfig,
		pullInterval:       PullInterval,
		pushInterval:       PushInterval,
		metricsInterval:    MetricsInterval,
	}

	password := strfmt.Password(config.Credentials.Password)
	apiURL, err := url.Parse(config.Credentials.URL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", config.Credentials.URL)
	}
	PapiURL, err := url.Parse(types.PAPIBaseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", types.PAPIBaseURL)
	}
	ret.scenarioList, err = ret.FetchScenariosListFromDB()
	if err != nil {
		return nil, errors.Wrap(err, "while fetching scenarios from db")
	}
	ret.apiClient, err = apiclient.NewClient(&apiclient.Config{
		MachineID:      config.Credentials.Login,
		Password:       password,
		UserAgent:      fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:            apiURL,
		PapiURL:        PapiURL,
		VersionPrefix:  "v2",
		Scenarios:      ret.scenarioList,
		UpdateScenario: ret.FetchScenariosListFromDB,
	})

	return ret, err
}

func (a *apic) SyncDecisions() error {
	defer types.CatchPanic("lapi/syncDecisionsToCAPI")

	var cache models.AddSignalsRequestItemDecisions
	ticker := time.NewTicker(a.pushInterval)
	log.Infof("Start decisions sync to CrowdSec Central API (interval: %s)", PushInterval)

	for {
		select {
		case <-a.pushTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.metricsTomb.Kill(nil)
			log.Infof("push tomb is dying, sending cache (%d elements) before exiting", len(cache))
			if len(cache) == 0 {
				return nil
			}
			go a.SendDeletedDecisions(&cache)
			return nil
		case <-ticker.C:
			if len(cache) > 0 {
				a.mu.Lock()
				cacheCopy := cache
				cache = make([]*models.AddSignalsRequestItemDecisionsItem, 0)
				a.mu.Unlock()
				log.Infof("Signal push: %d signals to push", len(cacheCopy))
				go a.SendDeletedDecisions(&cacheCopy)
			}
		case deletedDecisions := <-a.DecisionDeleteChan:

			if a.consoleConfig.ShareManualDecisions != nil && *a.consoleConfig.ShareManualDecisions {
				var tmpDecisions []*models.AddSignalsRequestItemDecisionsItem
				log.Printf("got delete yo %+v", deletedDecisions)
				for _, decision := range deletedDecisions {

					x := &models.AddSignalsRequestItemDecisionsItem{
						Duration: types.StrPtr(*decision.Duration),
						ID:       new(int64),
						Origin:   types.StrPtr(*decision.Origin),
						Scenario: types.StrPtr(*decision.Scenario),
						Scope:    types.StrPtr(*decision.Scope),
						Type:     types.StrPtr(*decision.Type),
						Until:    decision.Until,
						Value:    types.StrPtr(*decision.Value),
					}
					if decision.Simulated != nil {
						x.Simulated = *decision.Simulated
					}
					tmpDecisions = append(tmpDecisions, x)
				}

				a.mu.Lock()
				cache = append(cache, tmpDecisions...)
				a.mu.Unlock()
			}
		}
	}

	// ticker := time.NewTicker(a.pushInterval)
	// var DeletedDecisionsCache models.AddSignalsRequestItemDecisions
	// DeletedDecisionsCache = make([]*models.AddSignalsRequestItemDecisionsItem, 0)

	// for {
	// 	select {
	// 	case <-ticker.C:
	// 		if len(DeletedDecisionsCache) > 0 {
	// 			log.Printf("dumping deleted decisions")
	// 			log.Printf(spew.Sdump(DeletedDecisionsCache))

	// 			DeletedDecisionsCache = make([]*models.AddSignalsRequestItemDecisionsItem, 0)
	// 		}
	// 	case deletedDecisions := <-a.DecisionDeleteChan:
	// 		//only share deletion if users wants to share manual decision
	// 		if a.consoleConfig.ShareManualDecisions != nil && *a.consoleConfig.ShareManualDecisions {
	// 			log.Printf("got delete yo %+v", deletedDecisions)
	// 			for _, decision := range deletedDecisions {

	// 				x := &models.AddSignalsRequestItemDecisionsItem{
	// 					Duration: types.StrPtr(*decision.Duration),
	// 					ID:       new(int64),
	// 					Origin:   types.StrPtr(*decision.Origin),
	// 					Scenario: types.StrPtr(*decision.Scenario),
	// 					Scope:    types.StrPtr(*decision.Scope),
	// 					Type:     types.StrPtr(*decision.Type),
	// 					Until:    decision.Until,
	// 					Value:    types.StrPtr(*decision.Value),
	// 				}
	// 				if decision.Simulated != nil {
	// 					x.Simulated = *decision.Simulated
	// 				}
	// 				DeletedDecisionsCache = append(DeletedDecisionsCache, x)
	// 			}
	// 		}
	// 	}
	// }
}

// keep track of all alerts in cache and push it to CAPI every PushInterval.
func (a *apic) Push() error {
	defer types.CatchPanic("lapi/pushToAPIC")

	var cache models.AddSignalsRequest
	ticker := time.NewTicker(a.pushInterval)
	log.Infof("Start push to CrowdSec Central API (interval: %s)", PushInterval)

	for {
		select {
		case <-a.pushTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.metricsTomb.Kill(nil)
			log.Infof("push tomb is dying, sending cache (%d elements) before exiting", len(cache))
			if len(cache) == 0 {
				return nil
			}
			go a.Send(&cache)
			return nil
		case <-ticker.C:
			if len(cache) > 0 {
				a.mu.Lock()
				cacheCopy := cache
				cache = make(models.AddSignalsRequest, 0)
				a.mu.Unlock()
				log.Infof("Signal push: %d signals to push", len(cacheCopy))
				go a.Send(&cacheCopy)
			}
		case alerts := <-a.AlertsAddChan:
			var signals []*models.AddSignalsRequestItem
			for _, alert := range alerts {
				if ok := shouldShareAlert(alert, a.consoleConfig); ok {
					signals = append(signals, alertToSignal(alert, getScenarioTrustOfAlert(alert)))
				}
			}
			a.mu.Lock()
			cache = append(cache, signals...)
			a.mu.Unlock()
		}
	}
}

func getScenarioTrustOfAlert(alert *models.Alert) string {
	scenarioTrust := "certified"
	if alert.ScenarioHash == nil || *alert.ScenarioHash == "" {
		scenarioTrust = "custom"
	} else if alert.ScenarioVersion == nil || *alert.ScenarioVersion == "" || *alert.ScenarioVersion == "?" {
		scenarioTrust = "tainted"
	}
	if len(alert.Decisions) > 0 {
		if *alert.Decisions[0].Origin == "cscli" {
			scenarioTrust = "manual"
		}
	}
	return scenarioTrust
}

func shouldShareAlert(alert *models.Alert, consoleConfig *csconfig.ConsoleConfig) bool {
	if *alert.Simulated {
		log.Debugf("simulation enabled for alert (id:%d), will not be sent to CAPI", alert.ID)
		return false
	}
	switch scenarioTrust := getScenarioTrustOfAlert(alert); scenarioTrust {
	case "manual":
		if !*consoleConfig.ShareManualDecisions {
			log.Debugf("manual decision generated an alert, doesn't send it to CAPI because options is disabled")
			return false
		}
	case "tainted":
		if !*consoleConfig.ShareTaintedScenarios {
			log.Debugf("tainted scenario generated an alert, doesn't send it to CAPI because options is disabled")
			return false
		}
	case "custom":
		if !*consoleConfig.ShareCustomScenarios {
			log.Debugf("custom scenario generated an alert, doesn't send it to CAPI because options is disabled")
			return false
		}
	}
	return true
}

func (a *apic) SendDeletedDecisions(cacheOrig *models.AddSignalsRequestItemDecisions) {

	var cache []*models.AddSignalsRequestItemDecisionsItem = *cacheOrig
	var send models.AddSignalsRequestItemDecisions

	bulkSize := 50
	pageStart := 0
	pageEnd := bulkSize

	for {

		if pageEnd >= len(cache) {
			send = cache[pageStart:]
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := a.apiClient.DecisionDelete.Add(ctx, &send)
			if err != nil {
				log.Errorf("Error while sending final chunk to central API : %s", err)
				return
			}
			break
		}
		send = cache[pageStart:pageEnd]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := a.apiClient.DecisionDelete.Add(ctx, &send)
		if err != nil {
			//we log it here as well, because the return value of func might be discarded
			log.Errorf("Error while sending chunk to central API : %s", err)
		}
		pageStart += bulkSize
		pageEnd += bulkSize
	}
}

func (a *apic) Send(cacheOrig *models.AddSignalsRequest) {
	/*we do have a problem with this :
	The apic.Push background routine reads from alertToPush chan.
	This chan is filled by Controller.CreateAlert

	If the chan apic.Send hangs, the alertToPush chan will become full,
	with means that Controller.CreateAlert is going to hang, blocking API worker(s).

	So instead, we prefer to cancel write.

	I don't know enough about gin to tell how much of an issue it can be.
	*/
	var cache []*models.AddSignalsRequestItem = *cacheOrig
	var send models.AddSignalsRequest

	bulkSize := 50
	pageStart := 0
	pageEnd := bulkSize

	for {

		if pageEnd >= len(cache) {
			send = cache[pageStart:]
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := a.apiClient.Signal.Add(ctx, &send)
			if err != nil {
				log.Errorf("Error while sending final chunk to central API : %s", err)
				return
			}
			break
		}
		send = cache[pageStart:pageEnd]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := a.apiClient.Signal.Add(ctx, &send)
		if err != nil {
			//we log it here as well, because the return value of func might be discarded
			log.Errorf("Error while sending chunk to central API : %s", err)
		}
		pageStart += bulkSize
		pageEnd += bulkSize
	}
}

func (a *apic) CAPIPullIsOld() (bool, error) {
	/*only pull community blocklist if it's older than 1h30 */
	alerts := a.dbClient.Ent.Alert.Query()
	alerts = alerts.Where(alert.HasDecisionsWith(decision.OriginEQ(database.CapiMachineID)))
	alerts = alerts.Where(alert.CreatedAtGTE(time.Now().UTC().Add(-time.Duration(1*time.Hour + 30*time.Minute)))) //nolint:unconvert
	count, err := alerts.Count(a.dbClient.CTX)
	if err != nil {
		return false, errors.Wrap(err, "while looking for CAPI alert")
	}
	if count > 0 {
		log.Printf("last CAPI pull is newer than 1h30, skip.")
		return false, nil
	}
	return true, nil
}

func (a *apic) HandleDeletedDecisions(deletedDecisions []*models.Decision, delete_counters map[string]map[string]int) (int, error) {
	var filter map[string][]string
	var nbDeleted int
	for _, decision := range deletedDecisions {
		if strings.ToLower(*decision.Scope) == "ip" {
			filter = make(map[string][]string, 1)
			filter["value"] = []string{*decision.Value}
		} else {
			filter = make(map[string][]string, 3)
			filter["value"] = []string{*decision.Value}
			filter["type"] = []string{*decision.Type}
			filter["scopes"] = []string{*decision.Scope}
		}
		filter["origin"] = []string{*decision.Origin}

		dbCliRet, _, err := a.dbClient.SoftDeleteDecisionsWithFilter(filter)
		if err != nil {
			return 0, errors.Wrap(err, "deleting decisions error")
		}
		dbCliDel, err := strconv.Atoi(dbCliRet)
		if err != nil {
			return 0, errors.Wrapf(err, "converting db ret %d", dbCliDel)
		}
		updateCounterForDecision(delete_counters, decision, dbCliDel)
		nbDeleted += dbCliDel
	}
	return nbDeleted, nil

}

func createAlertsForDecisions(decisions []*models.Decision) []*models.Alert {
	newAlerts := make([]*models.Alert, 0)
	for _, decision := range decisions {
		found := false
		for _, sub := range newAlerts {
			if sub.Source.Scope == nil {
				log.Warningf("nil scope in %+v", sub)
				continue
			}
			if *decision.Origin == SCOPE_CAPI {
				if *sub.Source.Scope == SCOPE_CAPI {
					found = true
					break
				}
			} else if *decision.Origin == SCOPE_LISTS {
				if *sub.Source.Scope == *decision.Origin {
					if sub.Scenario == nil {
						log.Warningf("nil scenario in %+v", sub)
					}
					if *sub.Scenario == *decision.Scenario {
						found = true
						break
					}
				}
			} else {
				log.Warningf("unknown origin %s : %+v", *decision.Origin, decision)
			}
		}
		if !found {
			log.Debugf("Create entry for origin:%s scenario:%s", *decision.Origin, *decision.Scenario)
			newAlerts = append(newAlerts, createAlertForDecision(decision))
		}
	}
	return newAlerts
}

func createAlertForDecision(decision *models.Decision) *models.Alert {
	newAlert := &models.Alert{}
	newAlert.Source = &models.Source{}
	newAlert.Source.Scope = types.StrPtr("")
	if *decision.Origin == SCOPE_CAPI { //to make things more user friendly, we replace CAPI with community-blocklist
		newAlert.Scenario = types.StrPtr(SCOPE_CAPI)
		newAlert.Source.Scope = types.StrPtr(SCOPE_CAPI)
	} else if *decision.Origin == SCOPE_LISTS {
		newAlert.Scenario = types.StrPtr(*decision.Scenario)
		newAlert.Source.Scope = types.StrPtr(SCOPE_LISTS)
	} else {
		log.Warningf("unknown origin %s", *decision.Origin)
	}
	newAlert.Message = types.StrPtr("")
	newAlert.Source.Value = types.StrPtr("")
	newAlert.StartAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
	newAlert.StopAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
	newAlert.Capacity = types.Int32Ptr(0)
	newAlert.Simulated = types.BoolPtr(false)
	newAlert.EventsCount = types.Int32Ptr(0)
	newAlert.Leakspeed = types.StrPtr("")
	newAlert.ScenarioHash = types.StrPtr("")
	newAlert.ScenarioVersion = types.StrPtr("")
	newAlert.MachineID = database.CapiMachineID
	return newAlert
}

// This function takes in list of parent alerts and decisions and then pairs them up.
func fillAlertsWithDecisions(alerts []*models.Alert, decisions []*models.Decision, add_counters map[string]map[string]int) []*models.Alert {
	for _, decision := range decisions {
		//count and create separate alerts for each list
		updateCounterForDecision(add_counters, decision, 1)

		/*CAPI might send lower case scopes, unify it.*/
		switch strings.ToLower(*decision.Scope) {
		case "ip":
			*decision.Scope = types.Ip
		case "range":
			*decision.Scope = types.Range
		}
		found := false
		//add the individual decisions to the right list
		for idx, alert := range alerts {
			if *decision.Origin == SCOPE_CAPI {
				if *alert.Source.Scope == SCOPE_CAPI {
					alerts[idx].Decisions = append(alerts[idx].Decisions, decision)
					found = true
					break
				}
			} else if *decision.Origin == SCOPE_LISTS {
				if *alert.Source.Scope == SCOPE_LISTS && *alert.Scenario == *decision.Scenario {
					alerts[idx].Decisions = append(alerts[idx].Decisions, decision)
					found = true
					break
				}
			} else {
				log.Warningf("unknown origin %s", *decision.Origin)
			}
		}
		if !found {
			log.Warningf("Orphaned decision for %s - %s", *decision.Origin, *decision.Scenario)
		}
	}
	return alerts
}

func PapiError(err error) bool {
	log.Warningf("PAPI/ERROR : %s", err)
	return true
}

var PAPI_PULL_KEY = "papi:last_pull"

//PullPAPI is the long polling client for real-time decisions from PAPI
func (a *apic) PullPAPI() error {

	defer types.CatchPanic("lapi/PullPAPI")
	log.Infof("Starting Polling API Pull")

	if a.apiClient.PapiURL == nil {
		return errors.New("PAPI URL is nil")
	}
	c, err := client.NewClient(client.ClientOptions{
		SubscribeUrl:   *a.apiClient.PapiURL,
		Category:       "some-category",
		HttpClient:     a.apiClient.GetClient(),
		OnFailure:      PapiError,
		LoggingEnabled: true,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create PAPI client")
	}

	lastTimestamp := time.Now().UTC()
	lastTimestampStr, err := a.dbClient.GetConfigItem(PAPI_PULL_KEY)
	if err != nil {
		log.Warningf("failed to get liast timestamp -> %s", err)
	}
	//value doesn't exist, it's first time
	if lastTimestampStr == nil {
		binTime, err := lastTimestamp.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		a.dbClient.SetConfigItem(PAPI_PULL_KEY, string(binTime))
	} else {
		if err := lastTimestamp.UnmarshalText([]byte(*lastTimestampStr)); err != nil {
			return errors.Wrap(err, "failed to unmarshal last timestamp")
		}
	}

	log.Printf("starting polling at %s", lastTimestamp)
	for event := range c.Start(lastTimestamp) {
		//update last timestamp in database
		newTime := time.Now().UTC()
		binTime, err := newTime.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		if err := a.dbClient.SetConfigItem(PAPI_PULL_KEY, string(binTime)); err != nil {
			return errors.Wrap(err, "failed to set last timestamp")
		} else {
			log.Infof("set last timestamp to %s", newTime)
		}

		// do something with each event
		log.Printf("yoyoyo -> %+v", event)
		//log.Printf("yoyoyo -> %s", event)

		bin, err := json.Marshal(event.Data)
		if err != nil {
			return errors.Wrap(err, "failed to marshal event data")
		}
		alert := models.Alert{}

		if err := json.Unmarshal(bin, &alert); err != nil {
			return errors.Wrap(err, "failed to unmarshal event data")
		}

		/*Fix the alert with missing mandatory items*/
		alert.StartAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		alert.StopAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		alert.EventsCount = types.Int32Ptr(0)
		alert.Capacity = types.Int32Ptr(0)
		alert.Leakspeed = types.StrPtr("")
		alert.Simulated = types.BoolPtr(false)
		alert.ScenarioHash = types.StrPtr("")
		alert.ScenarioVersion = types.StrPtr("")
		alert.Message = types.StrPtr("")
		alert.Scenario = types.StrPtr("")
		alert.Source = &models.Source{}
		alert.Source.Scope = types.StrPtr(SCOPE_CAPI)
		alert.Source.Value = types.StrPtr("")

		a.AlertsAddChan <- []*models.Alert{&alert}
		ret, err := a.dbClient.CreateOrUpdateAlert("", &alert)
		if err != nil {
			log.Errorf("Failed to create alerts in DB: %s", err)
		}
		log.Printf("ret--> %s", ret)

	}
	return nil
}

//we receive only one list of decisions, that we need to break-up :
// one alert for "community blocklist"
// one alert per list we're subscribed to
func (a *apic) PullTop() error {
	var err error

	if lastPullIsOld, err := a.CAPIPullIsOld(); err != nil {
		return err
	} else if !lastPullIsOld {
		return nil
	}

	data, _, err := a.apiClient.Decisions.GetStream(context.Background(), apiclient.DecisionsStreamOpts{Startup: a.startup})
	if err != nil {
		return errors.Wrap(err, "get stream")
	}
	a.startup = false
	/*to count additions/deletions across lists*/

	add_counters, delete_counters := makeAddAndDeleteCounters()
	// process deleted decisions
	if nbDeleted, err := a.HandleDeletedDecisions(data.Deleted, delete_counters); err != nil {
		return err
	} else {
		log.Printf("capi/community-blocklist : %d explicit deletions", nbDeleted)
	}

	if len(data.New) == 0 {
		log.Infof("capi/community-blocklist : received 0 new entries (expected if you just installed crowdsec)")
		return nil
	}

	//we receive only one list of decisions, that we need to break-up :
	// one alert for "community blocklist"
	// one alert per list we're subscribed to
	alertsFromCapi := createAlertsForDecisions(data.New)
	alertsFromCapi = fillAlertsWithDecisions(alertsFromCapi, data.New, add_counters)

	for idx, alert := range alertsFromCapi {
		alertsFromCapi[idx] = setAlertScenario(add_counters, delete_counters, alert)
		log.Debugf("%s has %d decisions", *alertsFromCapi[idx].Source.Scope, len(alertsFromCapi[idx].Decisions))
		alertID, inserted, deleted, err := a.dbClient.UpdateCommunityBlocklist(alertsFromCapi[idx])
		if err != nil {
			return errors.Wrapf(err, "while saving alert from %s", *alertsFromCapi[idx].Source.Scope)
		}
		log.Printf("%s : added %d entries, deleted %d entries (alert:%d)", *alertsFromCapi[idx].Source.Scope, inserted, deleted, alertID)
	}
	return nil
}

func setAlertScenario(add_counters map[string]map[string]int, delete_counters map[string]map[string]int, alert *models.Alert) *models.Alert {
	if *alert.Source.Scope == SCOPE_CAPI {
		*alert.Source.Scope = SCOPE_CAPI_ALIAS
		alert.Scenario = types.StrPtr(fmt.Sprintf("update : +%d/-%d IPs", add_counters[SCOPE_CAPI]["all"], delete_counters[SCOPE_CAPI]["all"]))
	} else if *alert.Source.Scope == SCOPE_LISTS {
		*alert.Source.Scope = fmt.Sprintf("%s:%s", SCOPE_LISTS, *alert.Scenario)
		alert.Scenario = types.StrPtr(fmt.Sprintf("update : +%d/-%d IPs", add_counters[SCOPE_LISTS][*alert.Scenario], delete_counters[SCOPE_LISTS][*alert.Scenario]))
	}
	return alert
}

func (a *apic) Pull() error {
	defer types.CatchPanic("lapi/pullFromAPIC")
	log.Infof("Start pull from CrowdSec Central API (interval: %s)", PullInterval)

	toldOnce := false
	for {
		scenario, err := a.FetchScenariosListFromDB()
		if err != nil {
			log.Errorf("unable to fetch scenarios from db: %s", err)
		}
		if len(scenario) > 0 {
			break
		}
		if !toldOnce {
			log.Warning("scenario list is empty, will not pull yet")
			toldOnce = true
		}
		time.Sleep(1 * time.Second)
	}
	if err := a.PullTop(); err != nil {
		log.Errorf("capi pull top: %s", err)
	}
	ticker := time.NewTicker(a.pullInterval)
	for {
		select {
		case <-ticker.C:
			if err := a.PullTop(); err != nil {
				log.Errorf("capi pull top: %s", err)
				continue
			}
		case <-a.pullTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.metricsTomb.Kill(nil)
			a.pushTomb.Kill(nil)
			return nil
		}
	}
}

func (a *apic) GetMetrics() (*models.Metrics, error) {
	metric := &models.Metrics{
		ApilVersion: types.StrPtr(cwversion.VersionStr()),
		Machines:    make([]*models.MetricsAgentInfo, 0),
		Bouncers:    make([]*models.MetricsBouncerInfo, 0),
	}
	machines, err := a.dbClient.ListMachines()
	if err != nil {
		return metric, err
	}
	bouncers, err := a.dbClient.ListBouncers()
	if err != nil {
		return metric, err
	}
	var lastpush string
	for _, machine := range machines {
		if machine.LastPush == nil {
			lastpush = time.Time{}.String()
		} else {
			lastpush = machine.LastPush.String()
		}
		m := &models.MetricsAgentInfo{
			Version:    machine.Version,
			Name:       machine.MachineId,
			LastUpdate: machine.UpdatedAt.String(),
			LastPush:   lastpush,
		}
		metric.Machines = append(metric.Machines, m)
	}

	for _, bouncer := range bouncers {
		m := &models.MetricsBouncerInfo{
			Version:    bouncer.Version,
			CustomName: bouncer.Name,
			Name:       bouncer.Type,
			LastPull:   bouncer.LastPull.String(),
		}
		metric.Bouncers = append(metric.Bouncers, m)
	}
	return metric, nil
}

func (a *apic) SendMetrics() error {
	defer types.CatchPanic("lapi/metricsToAPIC")

	metrics, err := a.GetMetrics()
	if err != nil {
		log.Errorf("unable to get metrics (%s), will retry", err)
	}
	_, _, err = a.apiClient.Metrics.Add(context.Background(), metrics)
	if err != nil {
		log.Errorf("unable to send metrics (%s), will retry", err)
	}
	log.Infof("capi metrics: metrics sent successfully")
	log.Infof("Start send metrics to CrowdSec Central API (interval: %s)", MetricsInterval)
	ticker := time.NewTicker(a.metricsInterval)
	for {
		select {
		case <-ticker.C:
			metrics, err := a.GetMetrics()
			if err != nil {
				log.Errorf("unable to get metrics (%s), will retry", err)
			}
			_, _, err = a.apiClient.Metrics.Add(context.Background(), metrics)
			if err != nil {
				log.Errorf("capi metrics: failed: %s", err)
			} else {
				log.Infof("capi metrics: metrics sent successfully")
			}
		case <-a.metricsTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.pushTomb.Kill(nil)
			return nil
		}
	}
}

func (a *apic) Shutdown() {
	a.pushTomb.Kill(nil)
	a.pullTomb.Kill(nil)
	a.metricsTomb.Kill(nil)
}

func makeAddAndDeleteCounters() (map[string]map[string]int, map[string]map[string]int) {
	add_counters := make(map[string]map[string]int)
	add_counters[SCOPE_CAPI] = make(map[string]int)
	add_counters[SCOPE_LISTS] = make(map[string]int)

	delete_counters := make(map[string]map[string]int)
	delete_counters[SCOPE_CAPI] = make(map[string]int)
	delete_counters[SCOPE_LISTS] = make(map[string]int)

	return add_counters, delete_counters
}

func updateCounterForDecision(counter map[string]map[string]int, decision *models.Decision, totalDecisions int) {
	if *decision.Origin == SCOPE_CAPI {
		counter[*decision.Origin]["all"] += totalDecisions
		return
	} else if *decision.Origin == SCOPE_LISTS {
		counter[*decision.Origin][*decision.Scenario] += totalDecisions
	}
	log.Warningf("Unknown origin %s", *decision.Origin)
}
