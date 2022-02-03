package apiserver

import (
	"context"
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

	"gopkg.in/tomb.v2"
)

const (
	PullInterval    = "2h"
	PushInterval    = "30s"
	MetricsInterval = "30m"
)

type apic struct {
	pullInterval    time.Duration
	pushInterval    time.Duration
	metricsInterval time.Duration
	dbClient        *database.Client
	apiClient       *apiclient.ApiClient
	alertToPush     chan []*models.Alert
	mu              sync.Mutex
	pushTomb        tomb.Tomb
	pullTomb        tomb.Tomb
	metricsTomb     tomb.Tomb
	startup         bool
	credentials     *csconfig.ApiCredentialsCfg
	scenarioList    []string
	consoleConfig   *csconfig.ConsoleConfig
}

func IsInSlice(a string, b []string) bool {
	for _, v := range b {
		if a == v {
			return true
		}
	}
	return false
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
			if !IsInSlice(sv, scenarios) && sv != "" {
				scenarios = append(scenarios, sv)
			}
		}
	}
	log.Debugf("Returning list of scenarios : %+v", scenarios)
	return scenarios, nil
}

func AlertToSignal(alert *models.Alert, scenarioTrust string) *models.AddSignalsRequestItem {
	return &models.AddSignalsRequestItem{
		Message:         alert.Message,
		Scenario:        alert.Scenario,
		ScenarioHash:    alert.ScenarioHash,
		ScenarioVersion: alert.ScenarioVersion,
		Source:          alert.Source,
		StartAt:         alert.StartAt,
		StopAt:          alert.StopAt,
		CreatedAt:       alert.CreatedAt,
		MachineID:       alert.MachineID,
		ScenarioTrust:   &scenarioTrust,
	}
}

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client, consoleConfig *csconfig.ConsoleConfig) (*apic, error) {
	var err error
	ret := &apic{
		alertToPush:   make(chan []*models.Alert),
		dbClient:      dbClient,
		mu:            sync.Mutex{},
		startup:       true,
		credentials:   config.Credentials,
		pullTomb:      tomb.Tomb{},
		pushTomb:      tomb.Tomb{},
		metricsTomb:   tomb.Tomb{},
		scenarioList:  make([]string, 0),
		consoleConfig: consoleConfig,
	}

	ret.pullInterval, err = time.ParseDuration(PullInterval)
	if err != nil {
		return ret, err
	}
	ret.pushInterval, err = time.ParseDuration(PushInterval)
	if err != nil {
		return ret, err
	}
	ret.metricsInterval, err = time.ParseDuration(MetricsInterval)
	if err != nil {
		return ret, err
	}

	password := strfmt.Password(config.Credentials.Password)
	apiURL, err := url.Parse(config.Credentials.URL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", config.Credentials.URL)
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
		VersionPrefix:  "v2",
		Scenarios:      ret.scenarioList,
		UpdateScenario: ret.FetchScenariosListFromDB,
	})
	return ret, err
}

func (a *apic) Push() error {
	defer types.CatchPanic("lapi/pushToAPIC")

	var cache models.AddSignalsRequest
	ticker := time.NewTicker(a.pushInterval)
	log.Infof("start crowdsec api push (interval: %s)", PushInterval)

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
		case alerts := <-a.alertToPush:
			var signals []*models.AddSignalsRequestItem
			for _, alert := range alerts {
				if *alert.Simulated {
					log.Debugf("simulation enabled for alert (id:%d), will not be sent to CAPI", alert.ID)
					continue
				}
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
				switch scenarioTrust {
				case "manual":
					if !*a.consoleConfig.ShareManualDecisions {
						log.Debugf("manual decision generated an alert, doesn't send it to CAPI because options is disabled")
						continue
					}
				case "tainted":
					if !*a.consoleConfig.ShareTaintedScenarios {
						log.Debugf("tainted scenario generated an alert, doesn't send it to CAPI because options is disabled")
						continue
					}
				case "custom":
					if !*a.consoleConfig.ShareCustomScenarios {
						log.Debugf("custom scenario generated an alert, doesn't send it to CAPI because options is disabled")
						continue
					}
				}
				signals = append(signals, AlertToSignal(alert, scenarioTrust))
			}
			a.mu.Lock()
			cache = append(cache, signals...)
			a.mu.Unlock()
		}
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

var SCOPE_CAPI string = "CAPI"
var SCOPE_CAPI_ALIAS string = "crowdsecurity/community-blocklist" //we don't use "CAPI" directly, to make it less confusing for the user
var SCOPE_LISTS string = "lists"

func (a *apic) PullTop() error {
	var err error

	/*only pull community blocklist if it's older than 1h30 */
	alerts := a.dbClient.Ent.Alert.Query()
	alerts = alerts.Where(alert.HasDecisionsWith(decision.OriginEQ(database.CapiMachineID)))
	alerts = alerts.Where(alert.CreatedAtGTE(time.Now().UTC().Add(-time.Duration(1*time.Hour + 30*time.Minute))))
	count, err := alerts.Count(a.dbClient.CTX)
	if err != nil {
		return errors.Wrap(err, "while looking for CAPI alert")
	}
	if count > 0 {
		log.Printf("last CAPI pull is newer than 1h30, skip.")
		return nil
	}
	data, _, err := a.apiClient.Decisions.GetStream(context.Background(), a.startup, []string{})
	if err != nil {
		return errors.Wrap(err, "get stream")
	}
	if a.startup {
		a.startup = false
	}
	/*to count additions/deletions accross lists*/
	var add_counters map[string]map[string]int
	var delete_counters map[string]map[string]int

	add_counters = make(map[string]map[string]int)
	add_counters[SCOPE_CAPI] = make(map[string]int)
	add_counters[SCOPE_LISTS] = make(map[string]int)
	delete_counters = make(map[string]map[string]int)
	delete_counters[SCOPE_CAPI] = make(map[string]int)
	delete_counters[SCOPE_LISTS] = make(map[string]int)
	var filter map[string][]string
	var nbDeleted int
	// process deleted decisions
	for _, decision := range data.Deleted {
		//count individual deletions
		if *decision.Origin == SCOPE_CAPI {
			delete_counters[SCOPE_CAPI][*decision.Scenario]++
		} else if *decision.Origin == SCOPE_LISTS {
			delete_counters[SCOPE_LISTS][*decision.Scenario]++
		} else {
			log.Warningf("Unknown origin %s", *decision.Origin)
		}
		if strings.ToLower(*decision.Scope) == "ip" {
			filter = make(map[string][]string, 1)
			filter["value"] = []string{*decision.Value}
		} else {
			filter = make(map[string][]string, 3)
			filter["value"] = []string{*decision.Value}
			filter["type"] = []string{*decision.Type}
			filter["value"] = []string{*decision.Scope}
		}

		dbCliRet, err := a.dbClient.SoftDeleteDecisionsWithFilter(filter)
		if err != nil {
			return errors.Wrap(err, "deleting decisions error")
		}
		dbCliDel, err := strconv.Atoi(dbCliRet)
		if err != nil {
			return errors.Wrapf(err, "converting db ret %d", dbCliDel)
		}
		nbDeleted += dbCliDel
	}
	log.Printf("capi/community-blocklist : %d explicit deletions", nbDeleted)

	if len(data.New) == 0 {
		log.Warnf("capi/community-blocklist : received 0 new entries, CAPI failure ?")
		return nil
	}

	//we receive only one list of decisions, that we need to break-up :
	// one alert for "community blocklist"
	// one alert per list we're subscribed to
	var alertsFromCapi []*models.Alert
	alertsFromCapi = make([]*models.Alert, 0)

	//iterate over all new decisions, and simply create corresponding alerts
	for _, decision := range data.New {
		found := false
		for _, sub := range alertsFromCapi {
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
			newAlert := models.Alert{}
			newAlert.Message = types.StrPtr("")
			newAlert.Source = &models.Source{}
			if *decision.Origin == SCOPE_CAPI { //to make things more user friendly, we replace CAPI with community-blocklist
				newAlert.Source.Scope = types.StrPtr(SCOPE_CAPI)
				newAlert.Scenario = types.StrPtr(SCOPE_CAPI)
			} else if *decision.Origin == SCOPE_LISTS {
				newAlert.Source.Scope = types.StrPtr(SCOPE_LISTS)
				newAlert.Scenario = types.StrPtr(*decision.Scenario)
			} else {
				log.Warningf("unknown origin %s", *decision.Origin)
			}
			newAlert.Source.Value = types.StrPtr("")
			newAlert.StartAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
			newAlert.StopAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
			newAlert.Capacity = types.Int32Ptr(0)
			newAlert.Simulated = types.BoolPtr(false)
			newAlert.EventsCount = types.Int32Ptr(int32(len(data.New)))
			newAlert.Leakspeed = types.StrPtr("")
			newAlert.ScenarioHash = types.StrPtr("")
			newAlert.ScenarioVersion = types.StrPtr("")
			newAlert.MachineID = database.CapiMachineID
			alertsFromCapi = append(alertsFromCapi, &newAlert)
		}
	}

	//iterate a second time and fill the alerts with the new decisions
	for _, decision := range data.New {
		//count and create separate alerts for each list
		if *decision.Origin == SCOPE_CAPI {
			add_counters[SCOPE_CAPI]["all"]++
		} else if *decision.Origin == SCOPE_LISTS {
			add_counters[SCOPE_LISTS][*decision.Scenario]++
		} else {
			log.Warningf("Unknown origin %s", *decision.Origin)
		}

		/*CAPI might send lower case scopes, unify it.*/
		switch strings.ToLower(*decision.Scope) {
		case "ip":
			*decision.Scope = types.Ip
		case "range":
			*decision.Scope = types.Range
		}
		found := false
		//add the individual decisions to the right list
		for idx, alert := range alertsFromCapi {
			if *decision.Origin == SCOPE_CAPI {
				if *alert.Source.Scope == SCOPE_CAPI {
					alertsFromCapi[idx].Decisions = append(alertsFromCapi[idx].Decisions, decision)
					found = true
					break
				}
			} else if *decision.Origin == SCOPE_LISTS {
				if *alert.Source.Scope == SCOPE_LISTS && *alert.Scenario == *decision.Scenario {
					alertsFromCapi[idx].Decisions = append(alertsFromCapi[idx].Decisions, decision)
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

	for idx, alert := range alertsFromCapi {
		formatted_update := ""

		if *alertsFromCapi[idx].Source.Scope == SCOPE_CAPI {
			*alertsFromCapi[idx].Source.Scope = SCOPE_CAPI_ALIAS
			formatted_update = fmt.Sprintf("update : +%d/-%d IPs", add_counters[SCOPE_CAPI]["all"], delete_counters[SCOPE_CAPI]["all"])
		} else if *alertsFromCapi[idx].Source.Scope == SCOPE_LISTS {
			*alertsFromCapi[idx].Source.Scope = fmt.Sprintf("%s:%s", SCOPE_LISTS, *alertsFromCapi[idx].Scenario)
			formatted_update = fmt.Sprintf("update : +%d/-%d IPs", add_counters[SCOPE_LISTS][*alert.Scenario], delete_counters[SCOPE_LISTS][*alert.Scenario])
		}
		alertsFromCapi[idx].Scenario = types.StrPtr(formatted_update)
		log.Debugf("%s has %d decisions", *alertsFromCapi[idx].Source.Scope, len(alertsFromCapi[idx].Decisions))
		alertID, inserted, deleted, err := a.dbClient.UpdateCommunityBlocklist(alertsFromCapi[idx])
		if err != nil {
			return errors.Wrapf(err, "while saving alert from %s", *alertsFromCapi[idx].Source.Scope)
		}
		log.Printf("%s : added %d entries, deleted %d entries (alert:%d)", *alertsFromCapi[idx].Source.Scope, inserted, deleted, alertID)
	}
	return nil
}

func (a *apic) Pull() error {
	defer types.CatchPanic("lapi/pullFromAPIC")
	log.Infof("start crowdsec api pull (interval: %s)", PullInterval)
	var err error

	scenario := a.scenarioList
	toldOnce := false
	for {
		if len(scenario) > 0 {
			break
		}
		if !toldOnce {
			log.Warningf("scenario list is empty, will not pull yet")
			toldOnce = true
		}
		time.Sleep(1 * time.Second)
		scenario, err = a.FetchScenariosListFromDB()
		if err != nil {
			log.Errorf("unable to fetch scenarios from db: %s", err)
		}
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
	version := cwversion.VersionStr()
	metric := &models.Metrics{
		ApilVersion: &version,
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
	log.Infof("start crowdsec api send metrics (interval: %s)", MetricsInterval)
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
				log.Errorf("capi metrics: failed: %s", err.Error())
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
