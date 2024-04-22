package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func (a *apic) GetUsageMetrics() (*models.AllMetrics, []int, error) {
	lpsMetrics, err := a.dbClient.GetLPsUsageMetrics()
	metricsIds := make([]int, 0)

	if err != nil {
		return nil, nil, err
	}

	//spew.Dump(lpsMetrics)

	bouncersMetrics, err := a.dbClient.GetBouncersUsageMetrics()
	if err != nil {
		return nil, nil, err
	}

	//spew.Dump(bouncersMetrics)

	allMetrics := &models.AllMetrics{}

	lpsCache := make(map[string]*ent.Machine)
	bouncersCache := make(map[string]*ent.Bouncer)

	for _, lpsMetric := range lpsMetrics {
		lpName := lpsMetric.GeneratedBy
		metrics := models.LogProcessorsMetricsItems0{}

		err := json.Unmarshal([]byte(lpsMetric.Payload), &metrics)
		if err != nil {
			log.Errorf("unable to unmarshal LPs metrics (%s)", err)
			continue
		}

		var lp *ent.Machine

		if _, ok := lpsCache[lpName]; !ok {
			lp, err = a.dbClient.QueryMachineByID(lpName)

			if err != nil {
				log.Errorf("unable to get LP information for %s: %s", lpName, err)
				continue
			}
		} else {
			lp = lpsCache[lpName]
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

		metrics.Name = lpName
		metrics.LastPush = lp.LastPush.UTC().Unix()

		allMetrics.LogProcessors = append(allMetrics.LogProcessors, models.LogProcessorsMetrics{&metrics})
		metricsIds = append(metricsIds, lpsMetric.ID)
	}

	for _, bouncersMetric := range bouncersMetrics {
		bouncerName := bouncersMetric.GeneratedBy
		metrics := models.RemediationComponentsMetricsItems0{}

		err := json.Unmarshal([]byte(bouncersMetric.Payload), &metrics)
		if err != nil {
			log.Errorf("unable to unmarshal bouncers metrics (%s)", err)
			continue
		}

		var bouncer *ent.Bouncer

		if _, ok := bouncersCache[bouncerName]; !ok {
			bouncer, err = a.dbClient.SelectBouncerByName(bouncerName)
			if err != nil {
				log.Errorf("unable to get bouncer information for %s: %s", bouncerName, err)
				continue
			}
		} else {
			bouncer = bouncersCache[bouncerName]
		}

		metrics.Os = &models.OSversion{
			Name:    bouncer.Osname,
			Version: bouncer.Osversion,
		}
		metrics.Type = bouncer.Type
		metrics.FeatureFlags = strings.Split(bouncer.Featureflags, ",")
		metrics.Version = &bouncer.Version
		metrics.Name = bouncerName
		metrics.LastPull = bouncer.LastPull.UTC().Unix()

		allMetrics.RemediationComponents = append(allMetrics.RemediationComponents, models.RemediationComponentsMetrics{&metrics})
		metricsIds = append(metricsIds, bouncersMetric.ID)
	}

	//bouncerInfos := make(map[string]string)

	//TODO: add LAPI metrics

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
			}
			/*jsonStr, err := json.Marshal(metrics)
			if err != nil {
				log.Errorf("unable to marshal usage metrics (%s)", err)
			}*/
			//fmt.Printf("Usage metrics: %s\n", string(jsonStr))
			_, _, err = a.apiClient.UsageMetrics.Add(context.Background(), metrics)

			if err != nil {
				log.Errorf("unable to send usage metrics: %s", err)
			} else {

				err = a.MarkUsageMetricsAsSent(metricsId)
				if err != nil {
					log.Errorf("unable to mark usage metrics as sent: %s", err)
				}
			}
		}
	}
}
