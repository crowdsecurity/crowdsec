package main

import (
	"context"
	"errors"
	"net/http"
        "github.com/sirupsen/logrus"
        "github.com/blackfireio/osinfo"
	"time"

	"gopkg.in/tomb.v2"

        "github.com/crowdsecurity/go-cs-lib/ptr"
        "github.com/crowdsecurity/go-cs-lib/trace"

        "github.com/crowdsecurity/crowdsec/pkg/acquisition"
        "github.com/crowdsecurity/crowdsec/pkg/apiclient"
        "github.com/crowdsecurity/crowdsec/pkg/cwhub"
        "github.com/crowdsecurity/crowdsec/pkg/cwversion"
        "github.com/crowdsecurity/crowdsec/pkg/fflag"
        "github.com/crowdsecurity/crowdsec/pkg/models"
)

// MetricsProvider collects metrics from the LP and sends them to the LAPI
type MetricsProvider struct {
	apic *apiclient.ApiClient
	interval time.Duration
	static staticMetrics
	logger *logrus.Entry
}

type staticMetrics struct {
	osName            string
	osVersion         string
	startupTS         int64
	featureFlags      []string
	consoleOptions    []string
	datasourceMap     map[string]int64
	hubState	  models.HubItems
}

func getHubState(hub *cwhub.Hub) models.HubItems {
	ret := models.HubItems{}

	for _, itemType := range cwhub.ItemTypes {
		items, _ := hub.GetInstalledItems(itemType)
		for _, item := range items {
			status := "official"
			if item.State.IsLocal() {
				status = "custom"
			}
			if item.State.Tainted {
				status = "tainted"
			}
			ret[item.FQName()] = models.HubItem{
				Version: item.Version,
				Status:  status,
			}
		}
	}

	return ret
}

// newStaticMetrics is called when the process starts, or reloads the configuration
func newStaticMetrics(consoleOptions []string, datasources []acquisition.DataSource, hub *cwhub.Hub) staticMetrics {
	datasourceMap := map[string]int64{}

	for _, ds := range datasources {
		datasourceMap[ds.GetName()] += 1
	}

	osName, osVersion := detectOS()

	return staticMetrics{
		osName:         osName,
		osVersion:      osVersion,
		startupTS:      time.Now().Unix(),
		featureFlags:   fflag.Crowdsec.GetEnabledFeatures(),
		consoleOptions: consoleOptions,
		datasourceMap:  datasourceMap,
		hubState:       getHubState(hub),
	}
}

func detectOS() (string, string) {
	if cwversion.System == "docker" {
		return "docker", ""
	}

	osInfo, err := osinfo.GetOSInfo()
	if err != nil {
		return cwversion.System, "???"
	}

	return osInfo.Name, osInfo.Version
}


func NewMetricsProvider(apic *apiclient.ApiClient, interval time.Duration, logger *logrus.Entry,
		consoleOptions []string, datasources []acquisition.DataSource, hub *cwhub.Hub) *MetricsProvider {
	return &MetricsProvider{
		apic: apic,
		interval: interval,
		logger: logger,
		static: newStaticMetrics(consoleOptions, datasources, hub),
	}
}

func (m *MetricsProvider) metricsPayload() *models.AllMetrics {
	meta := &models.MetricsMeta{
		UtcStartupTimestamp: m.static.startupTS,
		WindowSizeSeconds: int64(m.interval.Seconds()),
	}

	os := &models.OSversion{
		Name: m.static.osName,
		Version: m.static.osVersion,
	}

	base := models.BaseMetrics{
		Meta: meta,
		Os: os,
		Version: ptr.Of(cwversion.VersionStr()),
		FeatureFlags: m.static.featureFlags,
	}

	item0 := &models.LogProcessorsMetricsItems0{
		BaseMetrics: base,
		ConsoleOptions: m.static.consoleOptions,
		Datasources: m.static.datasourceMap,
		HubItems: m.static.hubState,
	}

	// TODO: more metric details... ?

	return &models.AllMetrics{
                LogProcessors: []models.LogProcessorsMetrics{{item0}},
	}
}


func (m *MetricsProvider) Run(ctx context.Context, myTomb *tomb.Tomb) error {
	defer trace.CatchPanic("crowdsec/MetricsProvider.Run")

	if m.interval == time.Duration(0) {
		return nil
	}

	met := m.metricsPayload()

	ticker := time.NewTicker(m.interval)

	for {
		select {
		case <-ticker.C:
			met.LogProcessors[0][0].Meta.UtcNowTimestamp = time.Now().Unix()

			ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			_, resp, err := m.apic.UsageMetrics.Add(ctxTime, met)
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				m.logger.Warnf("timeout sending lp metrics")
				continue
			case err != nil:
				m.logger.Warnf("failed to send lp metrics: %s", err)
				continue
			}

			if resp.Response.StatusCode != http.StatusCreated {
				m.logger.Warnf("failed to send lp metrics: %s", resp.Response.Status)
				continue
			}

			m.logger.Tracef("lp usage metrics sent")
		case <-myTomb.Dying():
			ticker.Stop()
			return nil
		}
	}
}
