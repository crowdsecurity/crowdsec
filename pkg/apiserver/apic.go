package apiserver

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
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

func AlertToSignal(alert *models.Alert) *models.AddSignalsRequestItem {
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
	}
}

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client) (*apic, error) {
	var err error
	ret := &apic{
		alertToPush:  make(chan []*models.Alert),
		dbClient:     dbClient,
		mu:           sync.Mutex{},
		startup:      true,
		credentials:  config.Credentials,
		pullTomb:     tomb.Tomb{},
		pushTomb:     tomb.Tomb{},
		metricsTomb:  tomb.Tomb{},
		scenarioList: make([]string, 0),
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
	return ret, nil
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
			err := a.Send(&cache)
			return err
		case <-ticker.C:
			if len(cache) > 0 {
				a.mu.Lock()
				cacheCopy := cache
				cache = make(models.AddSignalsRequest, 0)
				a.mu.Unlock()
				log.Infof("Signal push: %d signals to push", len(cacheCopy))
				err := a.Send(&cacheCopy)
				if err != nil {
					log.Errorf("while sending signal to Central API : %s", err)
					log.Debugf("dump: %+v", cacheCopy)
					/*
						even in case of error, we don't want to return here, or we need to kill everything.
						this go-routine is in charge of pushing the signals to LAPI and is emptying the CAPIChan
					*/
				}
			}
		case alerts := <-a.alertToPush:
			var signals []*models.AddSignalsRequestItem
			for _, alert := range alerts {
				signals = append(signals, AlertToSignal(alert))
			}
			a.mu.Lock()
			cache = append(cache, signals...)
			a.mu.Unlock()
		}
	}
}

func (a *apic) Send(cache *models.AddSignalsRequest) error {
	/*we do have a problem with this :
	The apic.Push background routine reads from alertToPush chan.
	This chan is filled by Controller.CreateAlert

	If the chan apic.Send hangs, the alertToPush chan will become full,
	with means that Controller.CreateAlert is going to hang, blocking API worker(s).

	So instead, we prefer to cancel write.

	I don't know enough about gin to tell how much of an issue it can be.
	*/
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := a.apiClient.Signal.Add(ctx, cache)
	return err
}

func (a *apic) PullTop() error {
	var err error

	data, _, err := a.apiClient.Decisions.GetStream(context.Background(), a.startup)
	if err != nil {
		return errors.Wrap(err, "get stream")
	}
	if a.startup {
		a.startup = false
	}
	// process deleted decisions
	var filter map[string][]string
	for _, decision := range data.Deleted {
		if strings.ToLower(*decision.Scope) == "ip" {
			filter = make(map[string][]string, 1)
			filter["value"] = []string{*decision.Value}
		} else {
			filter = make(map[string][]string, 3)
			filter["value"] = []string{*decision.Value}
			filter["type"] = []string{*decision.Type}
			filter["value"] = []string{*decision.Scope}
		}

		nbDeleted, err := a.dbClient.SoftDeleteDecisionsWithFilter(filter)
		if err != nil {
			return err
		}

		log.Printf("pull top: deleted %s entries", nbDeleted)
	}

	alertCreated, err := a.dbClient.Ent.Alert.
		Create().
		SetScenario(fmt.Sprintf("update : +%d/-%d IPs", len(data.New), len(data.Deleted))).
		SetSourceScope("Comunity blocklist").
		Save(a.dbClient.CTX)
	if err != nil {
		return errors.Wrap(err, "create alert from crowdsec-api")
	}

	// process new decisions
	for _, decision := range data.New {
		/*ensure scope makes sense no matter what consensus gives*/
		if strings.ToLower(*decision.Scope) == "ip" {
			*decision.Scope = types.Ip
		} else if strings.ToLower(*decision.Scope) == "range" {
			*decision.Scope = types.Range
		}

		duration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			return errors.Wrapf(err, "parse decision duration '%s':", *decision.Duration)
		}
		startIP, endIP, err := controllers.GetIpsFromIpRange(*decision.Value)
		if err != nil {
			return errors.Wrapf(err, "ip to int '%s':", *decision.Value)
		}

		_, err = a.dbClient.Ent.Decision.Create().
			SetUntil(time.Now().Add(duration)).
			SetScenario(*decision.Scenario).
			SetType(*decision.Type).
			SetStartIP(startIP).
			SetEndIP(endIP).
			SetValue(*decision.Value).
			SetScope(*decision.Scope).
			SetOrigin(*decision.Origin).
			SetOwner(alertCreated).Save(a.dbClient.CTX)
		if err != nil {
			return errors.Wrap(err, "decision creation from crowdsec-api:")
		}
	}
	log.Printf("pull top: added %d entries", len(data.New))
	return nil
}

func (a *apic) Pull() error {
	defer types.CatchPanic("lapi/pullFromAPIC")
	log.Infof("start crowdsec api pull (interval: %s)", PullInterval)
	var err error

	scenario := a.scenarioList
	for {
		if len(scenario) > 0 {
			break
		}
		log.Warningf("scenario list is empty, will not pull yet")
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

func (a *apic) SendMetrics() error {
	defer types.CatchPanic("lapi/metricsToAPIC")

	log.Infof("start crowdsec api send metrics (interval: %s)", MetricsInterval)
	ticker := time.NewTicker(a.metricsInterval)
	for {
		select {
		case <-ticker.C:
			version := cwversion.VersionStr()
			metric := &models.Metrics{
				ApilVersion: &version,
				Machines:    make([]*models.MetricsSoftInfo, 0),
				Bouncers:    make([]*models.MetricsSoftInfo, 0),
			}
			machines, err := a.dbClient.ListMachines()
			if err != nil {
				return err
			}
			bouncers, err := a.dbClient.ListBouncers()
			if err != nil {
				return err
			}
			// models.metric structure : len(machines), len(bouncers), a.credentials.Login
			// _, _, err := a.apiClient.Metrics.Add(//*models.Metrics)
			for _, machine := range machines {
				m := &models.MetricsSoftInfo{
					Version: machine.Version,
					Name:    machine.MachineId,
				}
				metric.Machines = append(metric.Machines, m)
			}

			for _, bouncer := range bouncers {
				m := &models.MetricsSoftInfo{
					Version: bouncer.Version,
					Name:    bouncer.Type,
				}
				metric.Bouncers = append(metric.Bouncers, m)
			}
			_, _, err = a.apiClient.Metrics.Add(context.Background(), metric)
			if err != nil {
				return errors.Wrap(err, "sending metrics failed")
			}
			log.Infof("capi metrics: metrics sent successfully")
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
