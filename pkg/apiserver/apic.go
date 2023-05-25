package apiserver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
	"github.com/crowdsecurity/go-cs-lib/pkg/trace"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var (
	pullIntervalDefault    = time.Hour * 2
	pullIntervalDelta      = 5 * time.Minute
	pushIntervalDefault    = time.Second * 10
	pushIntervalDelta      = time.Second * 7
	metricsIntervalDefault = time.Minute * 30
	metricsIntervalDelta   = time.Minute * 15
)

var SCOPE_CAPI_ALIAS_ALIAS string = "crowdsecurity/community-blocklist" //we don't use "CAPI" directly, to make it less confusing for the user

type apic struct {
	// when changing the intervals in tests, always set *First too
	// or they can be negative
	pullInterval         time.Duration
	pullIntervalFirst    time.Duration
	pushInterval         time.Duration
	pushIntervalFirst    time.Duration
	metricsInterval      time.Duration
	metricsIntervalFirst time.Duration
	dbClient             *database.Client
	apiClient            *apiclient.ApiClient
	AlertsAddChan        chan []*models.Alert

	mu            sync.Mutex
	pushTomb      tomb.Tomb
	pullTomb      tomb.Tomb
	metricsTomb   tomb.Tomb
	startup       bool
	credentials   *csconfig.ApiCredentialsCfg
	scenarioList  []string
	consoleConfig *csconfig.ConsoleConfig
	isPulling     chan bool
	whitelists    *csconfig.CapiWhitelist
}

// randomDuration returns a duration value between d-delta and d+delta
func randomDuration(d time.Duration, delta time.Duration) time.Duration {
	return time.Duration(float64(d) + float64(delta)*(-1.0+2.0*rand.Float64()))
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
			Duration: ptr.Of(*decision.Duration),
			ID:       new(int64),
			Origin:   ptr.Of(*decision.Origin),
			Scenario: ptr.Of(*decision.Scenario),
			Scope:    ptr.Of(*decision.Scope),
			//Simulated: *decision.Simulated,
			Type:  ptr.Of(*decision.Type),
			Until: decision.Until,
			Value: ptr.Of(*decision.Value),
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

func alertToSignal(alert *models.Alert, scenarioTrust string, shareContext bool) *models.AddSignalsRequestItem {
	signal := &models.AddSignalsRequestItem{
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
	if shareContext {
		signal.Context = make([]*models.AddSignalsRequestItemContextItems0, 0)
		for _, meta := range alert.Meta {
			contextItem := models.AddSignalsRequestItemContextItems0{
				Key:   meta.Key,
				Value: meta.Value,
			}
			signal.Context = append(signal.Context, &contextItem)
		}
	}
	return signal
}

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client, consoleConfig *csconfig.ConsoleConfig, apicWhitelist *csconfig.CapiWhitelist) (*apic, error) {
	var err error
	ret := &apic{

		AlertsAddChan:        make(chan []*models.Alert),
		dbClient:             dbClient,
		mu:                   sync.Mutex{},
		startup:              true,
		credentials:          config.Credentials,
		pullTomb:             tomb.Tomb{},
		pushTomb:             tomb.Tomb{},
		metricsTomb:          tomb.Tomb{},
		scenarioList:         make([]string, 0),
		consoleConfig:        consoleConfig,
		pullInterval:         pullIntervalDefault,
		pullIntervalFirst:    randomDuration(pullIntervalDefault, pullIntervalDelta),
		pushInterval:         pushIntervalDefault,
		pushIntervalFirst:    randomDuration(pushIntervalDefault, pushIntervalDelta),
		metricsInterval:      metricsIntervalDefault,
		metricsIntervalFirst: randomDuration(metricsIntervalDefault, metricsIntervalDelta),
		isPulling:            make(chan bool, 1),
		whitelists:           apicWhitelist,
	}

	password := strfmt.Password(config.Credentials.Password)
	apiURL, err := url.Parse(config.Credentials.URL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", config.Credentials.URL)
	}
	papiURL, err := url.Parse(config.Credentials.PapiURL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", config.Credentials.PapiURL)
	}

	ret.scenarioList, err = ret.FetchScenariosListFromDB()
	if err != nil {
		return nil, errors.Wrap(err, "while fetching scenarios from db")
	}
	ret.apiClient, err = apiclient.NewClient(&apiclient.Config{
		MachineID:      config.Credentials.Login,
		Password:       password,
		UserAgent:      fmt.Sprintf("crowdsec/%s", version.String()),
		URL:            apiURL,
		PapiURL:        papiURL,
		VersionPrefix:  "v3",
		Scenarios:      ret.scenarioList,
		UpdateScenario: ret.FetchScenariosListFromDB,
	})
	if err != nil {
		return nil, errors.Wrap(err, "while creating api client")
	}

	// The watcher will be authenticated by the RoundTripper the first time it will call CAPI
	// Explicit authentication will provoke an useless supplementary call to CAPI
	scenarios, err := ret.FetchScenariosListFromDB()
	if err != nil {
		return ret, errors.Wrapf(err, "get scenario in db: %s", err)
	}

	authResp, _, err := ret.apiClient.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &config.Credentials.Login,
		Password:  &password,
		Scenarios: scenarios,
	})
	if err != nil {
		return ret, errors.Wrapf(err, "authenticate watcher (%s)", config.Credentials.Login)
	}

	if err := ret.apiClient.GetClient().Transport.(*apiclient.JWTTransport).Expiration.UnmarshalText([]byte(authResp.Expire)); err != nil {
		return ret, errors.Wrap(err, "unable to parse jwt expiration")
	}

	ret.apiClient.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token

	return ret, err
}

// keep track of all alerts in cache and push it to CAPI every PushInterval.
func (a *apic) Push() error {
	defer trace.CatchPanic("lapi/pushToAPIC")

	var cache models.AddSignalsRequest
	ticker := time.NewTicker(a.pushIntervalFirst)

	log.Infof("Start push to CrowdSec Central API (interval: %s once, then %s)", a.pushIntervalFirst.Round(time.Second), a.pushInterval)

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
			ticker.Reset(a.pushInterval)
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
					signals = append(signals, alertToSignal(alert, getScenarioTrustOfAlert(alert), *a.consoleConfig.ShareContext))
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
		if *alert.Decisions[0].Origin == types.CscliOrigin {
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
				log.Errorf("sending signal to central API: %s", err)
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
			log.Errorf("sending signal to central API: %s", err)
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
		updateCounterForDecision(delete_counters, decision.Origin, decision.Scenario, dbCliDel)
		nbDeleted += dbCliDel
	}
	return nbDeleted, nil
}

func (a *apic) HandleDeletedDecisionsV3(deletedDecisions []*modelscapi.GetDecisionsStreamResponseDeletedItem, delete_counters map[string]map[string]int) (int, error) {
	var filter map[string][]string
	var nbDeleted int
	for _, decisions := range deletedDecisions {
		scope := decisions.Scope
		for _, decision := range decisions.Decisions {
			if strings.ToLower(*scope) == "ip" {
				filter = make(map[string][]string, 1)
				filter["value"] = []string{decision}
			} else {
				filter = make(map[string][]string, 2)
				filter["value"] = []string{decision}
				filter["scopes"] = []string{*scope}
			}
			filter["origin"] = []string{types.CAPIOrigin}

			dbCliRet, _, err := a.dbClient.SoftDeleteDecisionsWithFilter(filter)
			if err != nil {
				return 0, errors.Wrap(err, "deleting decisions error")
			}
			dbCliDel, err := strconv.Atoi(dbCliRet)
			if err != nil {
				return 0, errors.Wrapf(err, "converting db ret %d", dbCliDel)
			}
			updateCounterForDecision(delete_counters, ptr.Of(types.CAPIOrigin), nil, dbCliDel)
			nbDeleted += dbCliDel
		}
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
			if *decision.Origin == types.CAPIOrigin {
				if *sub.Source.Scope == types.CAPIOrigin {
					found = true
					break
				}
			} else if *decision.Origin == types.ListOrigin {
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
	newAlert.Source.Scope = ptr.Of("")
	if *decision.Origin == types.CAPIOrigin { //to make things more user friendly, we replace CAPI with community-blocklist
		newAlert.Scenario = ptr.Of(types.CAPIOrigin)
		newAlert.Source.Scope = ptr.Of(types.CAPIOrigin)
	} else if *decision.Origin == types.ListOrigin {
		newAlert.Scenario = ptr.Of(*decision.Scenario)
		newAlert.Source.Scope = ptr.Of(types.ListOrigin)
	} else {
		log.Warningf("unknown origin %s", *decision.Origin)
	}
	newAlert.Message = ptr.Of("")
	newAlert.Source.Value = ptr.Of("")
	newAlert.StartAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	newAlert.StopAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
	newAlert.Capacity = ptr.Of(int32(0))
	newAlert.Simulated = ptr.Of(false)
	newAlert.EventsCount = ptr.Of(int32(0))
	newAlert.Leakspeed = ptr.Of("")
	newAlert.ScenarioHash = ptr.Of("")
	newAlert.ScenarioVersion = ptr.Of("")
	newAlert.MachineID = database.CapiMachineID
	return newAlert
}

// This function takes in list of parent alerts and decisions and then pairs them up.
func fillAlertsWithDecisions(alerts []*models.Alert, decisions []*models.Decision, add_counters map[string]map[string]int) []*models.Alert {
	for _, decision := range decisions {
		//count and create separate alerts for each list
		updateCounterForDecision(add_counters, decision.Origin, decision.Scenario, 1)

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
			if *decision.Origin == types.CAPIOrigin {
				if *alert.Source.Scope == types.CAPIOrigin {
					alerts[idx].Decisions = append(alerts[idx].Decisions, decision)
					found = true
					break
				}
			} else if *decision.Origin == types.ListOrigin {
				if *alert.Source.Scope == types.ListOrigin && *alert.Scenario == *decision.Scenario {
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

// we receive a list of decisions and links for blocklist and we need to create a list of alerts :
// one alert for "community blocklist"
// one alert per list we're subscribed to
func (a *apic) PullTop(forcePull bool) error {
	var err error

	//A mutex with TryLock would be a bit simpler
	//But go does not guarantee that TryLock will be able to acquire the lock even if it is available
	select {
	case a.isPulling <- true:
		defer func() {
			<-a.isPulling
		}()
	default:
		return errors.New("pull already in progress")
	}

	if !forcePull {
		if lastPullIsOld, err := a.CAPIPullIsOld(); err != nil {
			return err
		} else if !lastPullIsOld {
			return nil
		}
	}

	log.Infof("Starting community-blocklist update")

	data, _, err := a.apiClient.Decisions.GetStreamV3(context.Background(), apiclient.DecisionsStreamOpts{Startup: a.startup})
	if err != nil {
		return errors.Wrap(err, "get stream")
	}
	a.startup = false
	/*to count additions/deletions across lists*/

	log.Debugf("Received %d new decisions", len(data.New))
	log.Debugf("Received %d deleted decisions", len(data.Deleted))
	if data.Links != nil {
		log.Debugf("Received %d blocklists links", len(data.Links.Blocklists))
	}

	add_counters, delete_counters := makeAddAndDeleteCounters()
	// process deleted decisions
	if nbDeleted, err := a.HandleDeletedDecisionsV3(data.Deleted, delete_counters); err != nil {
		return err
	} else {
		log.Printf("capi/community-blocklist : %d explicit deletions", nbDeleted)
	}

	if len(data.New) == 0 {
		log.Infof("capi/community-blocklist : received 0 new entries (expected if you just installed crowdsec)")
		return nil
	}

	// create one alert for community blocklist using the first decision
	decisions := a.apiClient.Decisions.GetDecisionsFromGroups(data.New)
	//apply APIC specific whitelists
	decisions = a.ApplyApicWhitelists(decisions)

	alert := createAlertForDecision(decisions[0])
	alertsFromCapi := []*models.Alert{alert}
	alertsFromCapi = fillAlertsWithDecisions(alertsFromCapi, decisions, add_counters)

	err = a.SaveAlerts(alertsFromCapi, add_counters, delete_counters)
	if err != nil {
		return errors.Wrap(err, "while saving alerts")
	}

	// update blocklists
	if err := a.UpdateBlocklists(data.Links, add_counters); err != nil {
		return errors.Wrap(err, "while updating blocklists")
	}
	return nil
}

func (a *apic) ApplyApicWhitelists(decisions []*models.Decision) []*models.Decision {
	if a.whitelists == nil {
		return decisions
	}
	//deal with CAPI whitelists for fire. We want to avoid having a second list, so we shrink in place
	outIdx := 0
	for _, decision := range decisions {
		if decision.Value == nil {
			continue
		}
		skip := false
		ipval := net.ParseIP(*decision.Value)
		for _, cidr := range a.whitelists.Cidrs {
			if skip {
				break
			}
			if cidr.Contains(ipval) {
				log.Infof("%s from %s is whitelisted by %s", *decision.Value, *decision.Scenario, cidr.String())
				skip = true
			}
		}
		for _, ip := range a.whitelists.Ips {
			if skip {
				break
			}
			if ip != nil && ip.Equal(ipval) {
				log.Infof("%s from %s is whitelisted by %s", *decision.Value, *decision.Scenario, ip.String())
				skip = true
			}
		}
		if !skip {
			decisions[outIdx] = decision
			outIdx++
		}

	}
	//shrink the list, those are deleted items
	decisions = decisions[:outIdx]
	return decisions
}

func (a *apic) SaveAlerts(alertsFromCapi []*models.Alert, add_counters map[string]map[string]int, delete_counters map[string]map[string]int) error {
	for idx, alert := range alertsFromCapi {
		alertsFromCapi[idx] = setAlertScenario(add_counters, delete_counters, alert)
		log.Debugf("%s has %d decisions", *alertsFromCapi[idx].Source.Scope, len(alertsFromCapi[idx].Decisions))
		if a.dbClient.Type == "sqlite" && (a.dbClient.WalMode == nil || !*a.dbClient.WalMode) {
			log.Warningf("sqlite is not using WAL mode, LAPI might become unresponsive when inserting the community blocklist")
		}
		alertID, inserted, deleted, err := a.dbClient.UpdateCommunityBlocklist(alertsFromCapi[idx])
		if err != nil {
			return errors.Wrapf(err, "while saving alert from %s", *alertsFromCapi[idx].Source.Scope)
		}
		log.Printf("%s : added %d entries, deleted %d entries (alert:%d)", *alertsFromCapi[idx].Source.Scope, inserted, deleted, alertID)
	}

	return nil
}

func (a *apic) ShouldForcePullBlocklist(blocklist *modelscapi.BlocklistLink) (bool, error) {
	// we should force pull if the blocklist decisions are about to expire or there's no decision in the db
	alertQuery := a.dbClient.Ent.Alert.Query()
	alertQuery.Where(alert.SourceScopeEQ(fmt.Sprintf("%s:%s", types.ListOrigin, *blocklist.Name)))
	alertQuery.Order(ent.Desc(alert.FieldCreatedAt))
	alertInstance, err := alertQuery.First(context.Background())
	if err != nil {
		if ent.IsNotFound(err) {
			log.Debugf("no alert found for %s, force refresh", *blocklist.Name)
			return true, nil
		}
		return false, errors.Wrap(err, "while getting alert")
	}
	decisionQuery := a.dbClient.Ent.Decision.Query()
	decisionQuery.Where(decision.HasOwnerWith(alert.IDEQ(alertInstance.ID)))
	firstDecision, err := decisionQuery.First(context.Background())
	if err != nil {
		if ent.IsNotFound(err) {
			log.Debugf("no decision found for %s, force refresh", *blocklist.Name)
			return true, nil
		}
		return false, errors.Wrap(err, "while getting decision")
	}
	if firstDecision == nil || firstDecision.Until == nil || firstDecision.Until.Sub(time.Now().UTC()) < (a.pullInterval+15*time.Minute) {
		log.Debugf("at least one decision found for %s, expire soon, force refresh", *blocklist.Name)
		return true, nil
	}
	return false, nil
}

func (a *apic) UpdateBlocklists(links *modelscapi.GetDecisionsStreamResponseLinks, add_counters map[string]map[string]int) error {
	if links == nil {
		return nil
	}
	if links.Blocklists == nil {
		return nil
	}
	// we must use a different http client than apiClient's because the transport of apiClient is jwtTransport or here we have signed apis that are incompatibles
	// we can use the same baseUrl as the urls are absolute and the parse will take care of it
	defaultClient, err := apiclient.NewDefaultClient(a.apiClient.BaseURL, "", "", nil)
	if err != nil {
		return errors.Wrap(err, "while creating default client")
	}
	for _, blocklist := range links.Blocklists {
		if blocklist.Scope == nil {
			log.Warningf("blocklist has no scope")
			continue
		}
		if blocklist.Duration == nil {
			log.Warningf("blocklist has no duration")
			continue
		}
		forcePull, err := a.ShouldForcePullBlocklist(blocklist)
		if err != nil {
			return errors.Wrapf(err, "while checking if we should force pull blocklist %s", *blocklist.Name)
		}
		blocklistConfigItemName := fmt.Sprintf("blocklist:%s:last_pull", *blocklist.Name)
		var lastPullTimestamp *string
		if !forcePull {
			lastPullTimestamp, err = a.dbClient.GetConfigItem(blocklistConfigItemName)
			if err != nil {
				return errors.Wrapf(err, "while getting last pull timestamp for blocklist %s", *blocklist.Name)
			}
		}
		decisions, has_changed, err := defaultClient.Decisions.GetDecisionsFromBlocklist(context.Background(), blocklist, lastPullTimestamp)
		if err != nil {
			return errors.Wrapf(err, "while getting decisions from blocklist %s", *blocklist.Name)
		}
		if !has_changed {
			if lastPullTimestamp == nil {
				log.Infof("blocklist %s hasn't been modified or there was an error reading it, skipping", *blocklist.Name)
			} else {
				log.Infof("blocklist %s hasn't been modified since %s, skipping", *blocklist.Name, *lastPullTimestamp)
			}
			continue
		}
		err = a.dbClient.SetConfigItem(blocklistConfigItemName, time.Now().UTC().Format(http.TimeFormat))
		if err != nil {
			return errors.Wrapf(err, "while setting last pull timestamp for blocklist %s", *blocklist.Name)
		}
		if len(decisions) == 0 {
			log.Infof("blocklist %s has no decisions", *blocklist.Name)
			continue
		}
		//apply APIC specific whitelists
		decisions = a.ApplyApicWhitelists(decisions)
		alert := createAlertForDecision(decisions[0])
		alertsFromCapi := []*models.Alert{alert}
		alertsFromCapi = fillAlertsWithDecisions(alertsFromCapi, decisions, add_counters)

		err = a.SaveAlerts(alertsFromCapi, add_counters, nil)
		if err != nil {
			return errors.Wrapf(err, "while saving alert from blocklist %s", *blocklist.Name)
		}
	}
	return nil
}

func setAlertScenario(add_counters map[string]map[string]int, delete_counters map[string]map[string]int, alert *models.Alert) *models.Alert {
	if *alert.Source.Scope == types.CAPIOrigin {
		*alert.Source.Scope = SCOPE_CAPI_ALIAS_ALIAS
		alert.Scenario = ptr.Of(fmt.Sprintf("update : +%d/-%d IPs", add_counters[types.CAPIOrigin]["all"], delete_counters[types.CAPIOrigin]["all"]))
	} else if *alert.Source.Scope == types.ListOrigin {
		*alert.Source.Scope = fmt.Sprintf("%s:%s", types.ListOrigin, *alert.Scenario)
		alert.Scenario = ptr.Of(fmt.Sprintf("update : +%d/-%d IPs", add_counters[types.ListOrigin][*alert.Scenario], delete_counters[types.ListOrigin][*alert.Scenario]))
	}
	return alert
}

func (a *apic) Pull() error {
	defer trace.CatchPanic("lapi/pullFromAPIC")

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
	if err := a.PullTop(false); err != nil {
		log.Errorf("capi pull top: %s", err)
	}

	log.Infof("Start pull from CrowdSec Central API (interval: %s once, then %s)", a.pullIntervalFirst.Round(time.Second), a.pullInterval)
	ticker := time.NewTicker(a.pullIntervalFirst)

	for {
		select {
		case <-ticker.C:
			ticker.Reset(a.pullInterval)
			if err := a.PullTop(false); err != nil {
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
		ApilVersion: ptr.Of(version.String()),
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

func (a *apic) SendMetrics(stop chan (bool)) {
	defer trace.CatchPanic("lapi/metricsToAPIC")

	ticker := time.NewTicker(a.metricsIntervalFirst)

	log.Infof("Start send metrics to CrowdSec Central API (interval: %s once, then %s)", a.metricsIntervalFirst.Round(time.Second), a.metricsInterval)

	for {
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

		select {
		case <-stop:
			return
		case <-ticker.C:
			ticker.Reset(a.metricsInterval)
		case <-a.metricsTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.pushTomb.Kill(nil)
			return
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
	add_counters[types.CAPIOrigin] = make(map[string]int)
	add_counters[types.ListOrigin] = make(map[string]int)

	delete_counters := make(map[string]map[string]int)
	delete_counters[types.CAPIOrigin] = make(map[string]int)
	delete_counters[types.ListOrigin] = make(map[string]int)

	return add_counters, delete_counters
}

func updateCounterForDecision(counter map[string]map[string]int, origin *string, scenario *string, totalDecisions int) {
	if *origin == types.CAPIOrigin {
		counter[*origin]["all"] += totalDecisions
	} else if *origin == types.ListOrigin {
		counter[*origin][*scenario] += totalDecisions
	} else {
		log.Warningf("Unknown origin %s", *origin)
	}
}
