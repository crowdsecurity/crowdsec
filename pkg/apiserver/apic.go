package apiserver

import (
	"context"
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

func NewAPIC(config *csconfig.OnlineApiClientCfg, dbClient *database.Client) (*apic, error) {
	var err error
	var ret *apic

	apiclient.BaseURL, err = url.Parse(config.Credentials.URL)
	if err != nil {
		return ret, errors.Wrapf(err, "parse local API URL '%s': %v ", config.Credentials.URL, err.Error())
	}

	password := strfmt.Password(config.Credentials.Password)
	t := &apiclient.JWTTransport{
		MachineID: &config.Credentials.Login,
		Password:  &password,
	}

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

	return &apic{
		apiClient:       apiclient.NewClient(t.Client()),
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

	var cache []*models.Alert
	ticker := time.NewTicker(a.pushInterval)

	for {
		select {
		case <-a.pushTomb.Dying(): // if one apic routine is dying, do we kill the others?
			a.pullTomb.Kill(nil)
			a.metricsTomb.Kill(nil)
			log.Infof("push tomb is dying, sending cache (%d elements) before exiting", len(cache))
			err := a.Send(cache)
			return err
		case <-ticker.C:
			// flush
			a.mu.Lock()
			cacheCopy := cache
			cache = make([]*models.Alert, 0)
			a.mu.Unlock()

			err := a.Send(cacheCopy)
			if err != nil {
				return err
			}
		case alerts := <-a.alertToPush:
			a.mu.Lock()
			cache = append(cache, alerts...)
			a.mu.Unlock()
		}
	}
}

func (a *apic) Send(cache []*models.Alert) error {
	_, _, err := a.apiClient.Alerts.Add(context.Background(), cache)
	return err
}

func (a *apic) Pull() error {
	defer types.CatchPanic("apil/pullFromAPIC")

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

			// process new decisions
			for _, decision := range data.New {
				alertCreated, err := a.dbClient.Ent.Alert.
					Create().
					SetScenario(*decision.Scenario).
					SetSourceIp(*decision.Value).
					//SetSourceAsNumber(alert["as_num"]).
					//SetSourceAsName(alert["as_org"]).
					//SetSourceCountry(alert["country"]).
					Save(a.dbClient.CTX)
				if err != nil {
					return errors.Wrap(err, "create alert from crowdsec-api")
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
					SetOrigin("crowdsec-api").
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

			return nil
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
