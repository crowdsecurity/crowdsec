package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"slices"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (a *apic) GetUsageMetrics() (*models.AllMetrics, error) {
	lpsMetrics, err := a.dbClient.GetLPsUsageMetrics()

	if err != nil {
		return nil, err
	}

	spew.Dump(lpsMetrics)

	bouncersMetrics, err := a.dbClient.GetBouncersUsageMetrics()
	if err != nil {
		return nil, err
	}

	spew.Dump(bouncersMetrics)

	allMetrics := &models.AllMetrics{}

	allLps := a.dbClient.ListMachines()
	allBouncers := a.dbClient.ListBouncers()

	for _, lpsMetric := range lpsMetrics {
		lpName := lpsMetric.GeneratedBy
		metrics := models.LogProcessorsMetricsItems0{}

		err := json.Unmarshal([]byte(lpsMetric.Payload), &metrics)

		if err != nil {
			log.Errorf("unable to unmarshal LPs metrics (%s)", err)
			continue
		}

		lp, err := a.dbClient.QueryMachineByID(lpName)

		if err != nil {
			log.Errorf("unable to get LP information for %s: %s", lpName, err)
			continue
		}

		if lp.Hubstate != nil {
			metrics.HubItems = *lp.Hubstate
		}

		metrics.Os = &models.OSversion{
			Name:    lp.Osname,
			Version: lp.Osversion,
		}

		metrics.FeatureFlags = strings.Split(lp.Featureflags, ",")
		metrics.Version = &lp.Version
		//TODO: meta

	}

	//bouncerInfos := make(map[string]string)

	//TODO: add LAPI metrics

	return allMetrics, nil
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
			_, err := a.GetUsageMetrics()
			if err != nil {
				log.Errorf("unable to get usage metrics (%s)", err)
			}

		}
	}
}
