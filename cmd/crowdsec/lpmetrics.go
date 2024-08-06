package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const lpMetricsDefaultInterval = 30 * time.Minute

// MetricsProvider collects metrics from the LP and sends them to the LAPI
type MetricsProvider struct {
	apic     *apiclient.ApiClient
	interval time.Duration
	static   staticMetrics
	logger   *logrus.Entry
}

type staticMetrics struct {
	osName         string
	osVersion      string
	startupTS      int64
	featureFlags   []string
	consoleOptions []string
	datasourceMap  map[string]int64
	hubState       models.HubItems
}

func getHubState(hub *cwhub.Hub) models.HubItems {
	ret := models.HubItems{}

	for _, itemType := range cwhub.ItemTypes {
		ret[itemType] = []models.HubItem{}

		for _, item := range hub.GetInstalledByType(itemType, true) {
			status := "official"
			if item.State.IsLocal() {
				status = "custom"
			}
			if item.State.Tainted {
				status = "tainted"
			}
			ret[itemType] = append(ret[itemType], models.HubItem{
				Name:    item.Name,
				Status:  status,
				Version: item.Version,
			})
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

	osName, osVersion := version.DetectOS()

	return staticMetrics{
		osName:         osName,
		osVersion:      osVersion,
		startupTS:      time.Now().UTC().Unix(),
		featureFlags:   fflag.Crowdsec.GetEnabledFeatures(),
		consoleOptions: consoleOptions,
		datasourceMap:  datasourceMap,
		hubState:       getHubState(hub),
	}
}

func NewMetricsProvider(apic *apiclient.ApiClient, interval time.Duration, logger *logrus.Entry,
	consoleOptions []string, datasources []acquisition.DataSource, hub *cwhub.Hub) *MetricsProvider {
	return &MetricsProvider{
		apic:     apic,
		interval: interval,
		logger:   logger,
		static:   newStaticMetrics(consoleOptions, datasources, hub),
	}
}

func (m *MetricsProvider) metricsPayload() *models.AllMetrics {
	os := &models.OSversion{
		Name:    ptr.Of(m.static.osName),
		Version: ptr.Of(m.static.osVersion),
	}

	base := models.BaseMetrics{
		UtcStartupTimestamp: ptr.Of(m.static.startupTS),
		Os:                  os,
		Version:             ptr.Of(version.String()),
		FeatureFlags:        m.static.featureFlags,
		Metrics:             make([]*models.DetailedMetrics, 0),
	}

	met := &models.LogProcessorsMetrics{
		BaseMetrics: base,
		Datasources: m.static.datasourceMap,
		HubItems:    m.static.hubState,
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(m.interval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	})

	return &models.AllMetrics{
		LogProcessors: []*models.LogProcessorsMetrics{met},
	}
}

func (m *MetricsProvider) Run(ctx context.Context, myTomb *tomb.Tomb) error {
	defer trace.CatchPanic("crowdsec/MetricsProvider.Run")

	if m.interval == time.Duration(0) {
		return nil
	}

	met := m.metricsPayload()

	ticker := time.NewTicker(1) // Send on start

	for {
		select {
		case <-ticker.C:
			ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			_, resp, err := m.apic.UsageMetrics.Add(ctxTime, met)
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				m.logger.Warnf("timeout sending lp metrics")
				ticker.Reset(m.interval)
				continue
			case err != nil && resp != nil && resp.Response.StatusCode == http.StatusNotFound:
				m.logger.Warnf("metrics endpoint not found, older LAPI?")
				ticker.Reset(m.interval)
				continue
			case err != nil:
				m.logger.Warnf("failed to send lp metrics: %s", err)
				ticker.Reset(m.interval)
				continue
			}

			if resp.Response.StatusCode != http.StatusCreated {
				m.logger.Warnf("failed to send lp metrics: %s", resp.Response.Status)
				ticker.Reset(m.interval)
				continue
			}

			ticker.Reset(m.interval)

			m.logger.Tracef("lp usage metrics sent")
		case <-myTomb.Dying():
			ticker.Stop()
			return nil
		}
	}
}
