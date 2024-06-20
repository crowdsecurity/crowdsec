package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"slices"

	"github.com/blackfireio/osinfo"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type dbPayload struct {
	Metrics     *models.MetricsDetailItem `json:"metrics"`
	Meta        *models.MetricsMeta       `json:"meta"`
	Datasources map[string]int64          `json:"datasources"`
}

func detectOS() (string, string) {
	if version.System == "docker" {
		return "docker", ""
	}

	osInfo, err := osinfo.GetOSInfo()
	if err != nil {
		return version.System, "???"
	}

	return osInfo.Name, osInfo.Version
}

func (a *apic) GetUsageMetrics() (*models.AllMetrics, []int, error) {
	allMetrics := &models.AllMetrics{}
	metricsIds := make([]int, 0)

	lps, err := a.dbClient.ListMachines()
	if err != nil {
		return nil, nil, err
	}

	bouncers, err := a.dbClient.ListBouncers()
	if err != nil {
		return nil, nil, err
	}

	for _, bouncer := range bouncers {

		dbMetrics, err := a.dbClient.GetBouncerUsageMetricsByName(bouncer.Name)
		if err != nil {
			log.Errorf("unable to get bouncer usage metrics: %s", err)
			continue
		}

		rcMetrics := models.RemediationComponentsMetrics{}

		rcMetrics.Os = &models.OSversion{
			Name:    ptr.Of(bouncer.Osname),
			Version: ptr.Of(bouncer.Osversion),
		}
		rcMetrics.Type = bouncer.Type
		rcMetrics.FeatureFlags = strings.Split(bouncer.Featureflags, ",")
		rcMetrics.Version = ptr.Of(bouncer.Version)
		rcMetrics.Name = bouncer.Name
		rcMetrics.LastPull = bouncer.LastPull.UTC().Unix()

		rcMetrics.Metrics = make([]*models.MetricsDetailItem, 0)
		rcMetrics.Meta = &models.MetricsMeta{}

		//Might seem weird, but we duplicate the bouncers if we have multiple unsent metrics
		for _, dbMetric := range dbMetrics {

			dbPayload := &dbPayload{}
			//Append no matter what, if we cannot unmarshal, there's no way we'll be able to fix it automatically
			metricsIds = append(metricsIds, dbMetric.ID)

			err := json.Unmarshal([]byte(dbMetric.Payload), dbPayload)
			if err != nil {
				log.Errorf("unable to unmarshal bouncer metric (%s)", err)
				continue
			}

			rcMetrics.Meta.UtcStartupTimestamp = dbPayload.Meta.UtcStartupTimestamp
			rcMetrics.Meta.UtcNowTimestamp = dbPayload.Meta.UtcNowTimestamp
			rcMetrics.Meta.WindowSizeSeconds = dbPayload.Meta.WindowSizeSeconds

			rcMetrics.Metrics = append(rcMetrics.Metrics, dbPayload.Metrics)
			allMetrics.RemediationComponents = append(allMetrics.RemediationComponents, &rcMetrics)
		}

		//If we have no metrics, we still want to send the bouncer
		if len(rcMetrics.Metrics) == 0 {
			allMetrics.RemediationComponents = append(allMetrics.RemediationComponents, &rcMetrics)
		}
	}

	for _, lp := range lps {

		dbMetrics, err := a.dbClient.GetLPUsageMetricsByMachineID(lp.MachineId)
		if err != nil {
			log.Errorf("unable to get LP usage metrics: %s", err)
			continue
		}

		lpMetrics := models.LogProcessorsMetrics{}

		lpMetrics.Os = &models.OSversion{
			Name:    ptr.Of(lp.Osname),
			Version: ptr.Of(lp.Osversion),
		}
		lpMetrics.FeatureFlags = strings.Split(lp.Featureflags, ",")
		lpMetrics.Version = ptr.Of(lp.Version)
		lpMetrics.Name = lp.MachineId
		lpMetrics.LastPush = lp.LastPush.UTC().Unix()
		lpMetrics.LastUpdate = lp.UpdatedAt.UTC().Unix()

		lpMetrics.Datasources = make(map[string]int64)

		if lp.Hubstate != nil {
			lpMetrics.HubItems = *lp.Hubstate
		}

		lpMetrics.Metrics = make([]*models.MetricsDetailItem, 0)
		lpMetrics.Meta = &models.MetricsMeta{}

		for _, dbMetric := range dbMetrics {

			dbPayload := &dbPayload{}
			//Append no matter what, if we cannot unmarshal, there's no way we'll be able to fix it automatically
			metricsIds = append(metricsIds, dbMetric.ID)

			err := json.Unmarshal([]byte(dbMetric.Payload), dbPayload)
			if err != nil {
				log.Errorf("unable to unmarshal log processor metric (%s)", err)
				continue
			}

			lpMetrics.Meta.UtcStartupTimestamp = dbPayload.Meta.UtcStartupTimestamp
			lpMetrics.Meta.UtcNowTimestamp = dbPayload.Meta.UtcNowTimestamp
			lpMetrics.Meta.WindowSizeSeconds = dbPayload.Meta.WindowSizeSeconds

			for k, v := range dbPayload.Datasources {
				lpMetrics.Datasources[k] = v
			}

			lpMetrics.Metrics = append(lpMetrics.Metrics, dbPayload.Metrics)
			allMetrics.LogProcessors = append(allMetrics.LogProcessors, &lpMetrics)
		}

		//If we have no metrics, we still want to send the LP
		if len(lpMetrics.Metrics) == 0 {
			allMetrics.LogProcessors = append(allMetrics.LogProcessors, &lpMetrics)
		}
	}

	//FIXME: all of this should only be done once on startup/reload
	consoleOptions := strings.Join(csconfig.GetConfig().API.Server.ConsoleConfig.EnabledOptions(), ",")
	allMetrics.Lapi = &models.LapiMetrics{
		ConsoleOptions: models.ConsoleOptions{
			consoleOptions,
		},
	}

	osName, osVersion := detectOS()

	allMetrics.Lapi.Os = &models.OSversion{
		Name:    ptr.Of(osName),
		Version: ptr.Of(osVersion),
	}
	allMetrics.Lapi.Version = ptr.Of(version.String())
	allMetrics.Lapi.FeatureFlags = fflag.Crowdsec.GetEnabledFeatures()

	allMetrics.Lapi.Meta = &models.MetricsMeta{
		UtcStartupTimestamp: ptr.Of(time.Now().UTC().Unix()), //FIXME: should be the actual startup time
		UtcNowTimestamp:     ptr.Of(time.Now().UTC().Unix()),
		WindowSizeSeconds:   ptr.Of(int64(a.metricsInterval.Seconds())),
	}
	allMetrics.Lapi.Metrics = make([]*models.MetricsDetailItem, 0)

	//Force an actual slice to avoid non existing fields in the json
	if allMetrics.RemediationComponents == nil {
		allMetrics.RemediationComponents = make([]*models.RemediationComponentsMetrics, 0)
	}

	if allMetrics.LogProcessors == nil {
		allMetrics.LogProcessors = make([]*models.LogProcessorsMetrics, 0)
	}

	return allMetrics, metricsIds, nil
}

func (a *apic) MarkUsageMetricsAsSent(ids []int) error {
	return a.dbClient.MarkUsageMetricsAsSent(ids)
}

func (a *apic) GetMetrics() (*models.Metrics, error) {
	machines, err := a.dbClient.ListMachines()
	if err != nil {
		return nil, err
	}

	machinesInfo := make([]*models.MetricsAgentInfo, len(machines))

	for i, machine := range machines {
		machinesInfo[i] = &models.MetricsAgentInfo{
			Version:    machine.Version,
			Name:       machine.MachineId,
			LastUpdate: machine.UpdatedAt.Format(time.RFC3339),
			LastPush:   ptr.OrEmpty(machine.LastPush).Format(time.RFC3339),
		}
	}

	bouncers, err := a.dbClient.ListBouncers()
	if err != nil {
		return nil, err
	}

	bouncersInfo := make([]*models.MetricsBouncerInfo, len(bouncers))

	for i, bouncer := range bouncers {
		bouncersInfo[i] = &models.MetricsBouncerInfo{
			Version:    bouncer.Version,
			CustomName: bouncer.Name,
			Name:       bouncer.Type,
			LastPull:   bouncer.LastPull.Format(time.RFC3339),
		}
	}

	return &models.Metrics{
		ApilVersion: ptr.Of(version.String()),
		Machines:    machinesInfo,
		Bouncers:    bouncersInfo,
	}, nil
}

func (a *apic) fetchMachineIDs() ([]string, error) {
	machines, err := a.dbClient.ListMachines()
	if err != nil {
		return nil, err
	}

	ret := make([]string, len(machines))
	for i, machine := range machines {
		ret[i] = machine.MachineId
	}
	// sorted slices are required for the slices.Equal comparison
	slices.Sort(ret)

	return ret, nil
}

// SendMetrics sends metrics to the API server until it receives a stop signal.
//
// Metrics are sent at start, then at the randomized metricsIntervalFirst,
// then at regular metricsInterval. If a change is detected in the list
// of machines, the next metrics are sent immediately.
func (a *apic) SendMetrics(stop chan (bool)) {
	defer trace.CatchPanic("lapi/metricsToAPIC")

	// verify the list of machines every <checkInt> interval
	const checkInt = 20 * time.Second

	// intervals must always be > 0
	metInts := []time.Duration{1 * time.Millisecond, a.metricsIntervalFirst, a.metricsInterval}

	log.Infof("Start sending metrics to CrowdSec Central API (interval: %s once, then %s)",
		metInts[1].Round(time.Second), metInts[2])

	count := -1
	nextMetInt := func() time.Duration {
		if count < len(metInts)-1 {
			count++
		}

		return metInts[count]
	}

	machineIDs := []string{}

	reloadMachineIDs := func() {
		ids, err := a.fetchMachineIDs()
		if err != nil {
			log.Debugf("unable to get machines (%s), will retry", err)

			return
		}

		machineIDs = ids
	}

	// store the list of machine IDs to compare
	// with the next list
	reloadMachineIDs()

	checkTicker := time.NewTicker(checkInt)
	metTicker := time.NewTicker(nextMetInt())

	for {
		select {
		case <-stop:
			checkTicker.Stop()
			metTicker.Stop()

			return
		case <-checkTicker.C:
			oldIDs := machineIDs

			reloadMachineIDs()

			if !slices.Equal(oldIDs, machineIDs) {
				log.Infof("capi metrics: machines changed, immediate send")
				metTicker.Reset(1 * time.Millisecond)
			}
		case <-metTicker.C:
			metTicker.Stop()

			metrics, err := a.GetMetrics()
			if err != nil {
				log.Errorf("unable to get metrics (%s)", err)
			}
			// metrics are nil if they could not be retrieved
			if metrics != nil {
				log.Info("capi metrics: sending")

				_, _, err = a.apiClient.Metrics.Add(context.Background(), metrics)
				if err != nil {
					log.Errorf("capi metrics: failed: %s", err)
				}
			}

			metTicker.Reset(nextMetInt())
		case <-a.metricsTomb.Dying(): // if one apic routine is dying, do we kill the others?
			checkTicker.Stop()
			metTicker.Stop()
			a.pullTomb.Kill(nil)
			a.pushTomb.Kill(nil)

			return
		}
	}
}

func (a *apic) SendUsageMetrics() {
	defer trace.CatchPanic("lapi/usageMetricsToAPIC")

	ticker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-a.metricsTomb.Dying():
			//The normal metrics routine also kills push/pull tombs, does that make sense ?
			ticker.Stop()
			return
		case <-ticker.C:
			metrics, metricsId, err := a.GetUsageMetrics()
			if err != nil {
				log.Errorf("unable to get usage metrics: %s", err)
				continue
			}

			_, _, err = a.apiClient.UsageMetrics.Add(context.Background(), metrics)

			if err != nil {
				log.Errorf("unable to send usage metrics: %s", err)
				continue
			}
			err = a.MarkUsageMetricsAsSent(metricsId)
			if err != nil {
				log.Errorf("unable to mark usage metrics as sent: %s", err)
				continue
			}
			log.Infof("Usage metrics sent")
		}
	}
}
