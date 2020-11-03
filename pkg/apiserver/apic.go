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
	PullInterval    = "2m"
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
}

func IsInSlice(a string, b []string) bool {
	for _, v := range b {
		if a == v {
			return true
		}
	}
	return false
}

func FetchScenariosListFromDB(dbClient *database.Client) ([]string, error) {
	var scenarios []string

	machines, err := dbClient.ListMachines()
	if err != nil {
		return nil, errors.Wrap(err, "while listing machines")
	}
	//merge all scenarios together
	for _, v := range machines {
		machineScenarios := strings.Split(v.Scenarios, ",")
		log.Debugf("%d scenarios for machine %d", len(machineScenarios), v.ID)
		for _, sv := range machineScenarios {
			if !IsInSlice(sv, scenarios) {
				scenarios = append(scenarios, sv)
			}
		}
	}
	log.Debugf("Returning list of scenarios : %+v", scenarios)
	return scenarios, nil
}

func AlertToSignal(alert *models.Alert) *apiclient.Signal {
	return &apiclient.Signal{
		Message:         *alert.Message,
		Scenario:        *alert.Scenario,
		ScenarioHash:    *alert.ScenarioHash,
		ScenarioVersion: *alert.ScenarioVersion,
		Source:          alert.Source,
		StartAt:         *alert.StartAt,
		StopAt:          *alert.StopAt,
		CreatedAt:       alert.CreatedAt,
		MachineID:       alert.MachineID,
	}
}

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client) (*apic, error) {
	var err error
	var ret *apic

	pullInterval, err := time.ParseDuration(PullInterval)
	if err != nil {
		return ret, err
	}
	pushInterval, err := time.ParseDuration(PushInterval)
	if err != nil {
		return ret, err
	}
	metricsInterval, err := time.ParseDuration(MetricsInterval)
	if err != nil {
		return ret, err
	}

	password := strfmt.Password(config.Credentials.Password)
	apiURL, err := url.Parse(config.Credentials.URL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", config.Credentials.URL)
	}
	scenarios, err := FetchScenariosListFromDB(dbClient)
	if err != nil {
		return nil, errors.Wrap(err, "while fetching scenarios from db")
	}
	Client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     config.Credentials.Login,
		Password:      password,
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v2",
		Scenarios:     scenarios,
	})
	return &apic{
		apiClient:       Client,
		alertToPush:     make(chan []*models.Alert),
		dbClient:        dbClient,
		pullInterval:    pullInterval,
		pushInterval:    pushInterval,
		metricsInterval: metricsInterval,
		mu:              sync.Mutex{},
		startup:         true,
		credentials:     config.Credentials,
		pullTomb:        tomb.Tomb{},
		pushTomb:        tomb.Tomb{},
		metricsTomb:     tomb.Tomb{},
	}, nil
}

func (a *apic) Push() error {
	defer types.CatchPanic("apil/pushToAPIC")

	var cache []*apiclient.Signal
	ticker := time.NewTicker(a.pushInterval)
	log.Infof("start crowdsec api push (interval: %s)", PushInterval)

	for {
		select {
		case <-a.pushTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.metricsTomb.Kill(nil)
			log.Infof("push tomb is dying, sending cache (%d elements) before exiting", len(cache))
			err := a.Send(cache)
			return err
		case <-ticker.C:
			if len(cache) > 0 {
				a.mu.Lock()
				cacheCopy := cache
				cache = make([]*apiclient.Signal, 0)
				a.mu.Unlock()
				log.Infof("Signal push: %d signals to push", len(cacheCopy))
				err := a.Send(cacheCopy)
				if err != nil {
					log.Errorf("got an error while sending signal : %s", err)
					return err
				}
			}
		case alerts := <-a.alertToPush:
			a.mu.Lock()
			var signal *apiclient.Signal
			for _, alert := range alerts {
				signal = AlertToSignal(alert)
			}
			cache = append(cache, signal)
			a.mu.Unlock()
		}
	}
}

func (a *apic) Send(cache []*apiclient.Signal) error {
	_, _, err := a.apiClient.Signal.Add(context.Background(), cache)
	return err
}

func (a *apic) Pull() error {
	defer types.CatchPanic("apil/pullFromAPIC")
	log.Infof("start crowdsec api pull (interval: %s)", PullInterval)

	ticker := time.NewTicker(a.pullInterval)
	for {
		select {
		case <-ticker.C:
			data, _, err := a.apiClient.Decisions.GetStream(context.Background(), a.startup)
			if err != nil {
				return errors.Wrap(err, "pull top")
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
				SetScenario(fmt.Sprintf("consensus pull : %d IPs", len(data.New))).
				SetSourceScope("Crowdsec consensus").
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

		case <-a.pullTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.metricsTomb.Kill(nil)
			a.pushTomb.Kill(nil)
		}

	}
}

func (a *apic) SendMetrics() error {
	defer types.CatchPanic("apil/metricsToAPIC")

	log.Infof("start crowdsec api send metrics (interval: %s)", MetricsInterval)
	ticker := time.NewTicker(a.metricsInterval)
	for {
		select {
		case <-ticker.C:
			metric := &models.Metrics{}
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

			*metric.ApilVersion = cwversion.VersionStr()
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
				metric.Machines = append(metric.Bouncers, m)
			}
			log.Infof("TODO: send metrics : %+v", metric)
		case <-a.metricsTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.pushTomb.Kill(nil)
		}
	}
}

func (a *apic) Shutdown() {
	a.pushTomb.Kill(nil)
	a.pullTomb.Kill(nil)
	a.metricsTomb.Kill(nil)
}
