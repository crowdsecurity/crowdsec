package main

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	acquisitionMetrics "github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const lpMetricsDefaultInterval = 30 * time.Second

// MetricsProvider collects metrics from the LP and sends them to the LAPI
type MetricsProvider struct {
	apic     *apiclient.ApiClient
	interval time.Duration
	static   staticMetrics
	logger   *logrus.Entry
	// used to store the last collected value of a metric to compute the delta before sending it
	// Key is a concatenation of all labels
	metricsLastValues map[string]float64
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

// Key is the prom label
// Value is the name that will be used in the metrics payload
type labelsMapping map[string]string

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
	consoleOptions []string, datasources []acquisition.DataSource, hub *cwhub.Hub,
) *MetricsProvider {
	return &MetricsProvider{
		apic:              apic,
		interval:          interval,
		logger:            logger,
		static:            newStaticMetrics(consoleOptions, datasources, hub),
		metricsLastValues: make(map[string]float64),
	}
}

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}
	return ""
}

func getDeltaKey(labels []*io_prometheus_client.LabelPair) string {
	// Create a key from the labels to use as a map key
	// This is used to store the last value of the metric to compute the delta
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, label.GetName()+label.GetValue())
	}
	return strings.Join(parts, "")
}

func (m *MetricsProvider) gatherPromMetrics(metricsName []string, labelsMap labelsMapping, metricName string, unitType string) []*models.MetricsDetailItem {
	items := make([]*models.MetricsDetailItem, 0)

	promMetrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		m.logger.Errorf("failed to gather prometheus metrics: %s", err)
		return nil
	}

	for _, metricFamily := range promMetrics {
		if !slices.Contains(metricsName, metricFamily.GetName()) {
			continue
		}
		for _, metric := range metricFamily.GetMetric() {
			promLabels := metric.GetLabel()
			deltaKey := getDeltaKey(promLabels)
			metricsLabels := make(map[string]string)

			for labelKey, labelValue := range labelsMap {
				metricsLabels[labelKey] = getLabelValue(promLabels, labelValue)
			}

			currentValue := metric.GetCounter().GetValue()
			value := currentValue

			if lastValue, ok := m.metricsLastValues[deltaKey]; ok {
				value -= lastValue
				if value < 0 {
					m.logger.Warnf("negative delta for metric %s (labels: %+v), resetting to 0. This is probably a bug.", metricName, metricsLabels)
					value = 0
				}
				m.metricsLastValues[deltaKey] = currentValue
			} else {
				m.metricsLastValues[deltaKey] = currentValue
			}

			item := &models.MetricsDetailItem{
				Name:   ptr.Of(metricName),
				Unit:   ptr.Of(unitType),
				Labels: metricsLabels,
				Value:  ptr.Of(value),
			}
			m.logger.Infof("Gathered metric: %s, item: %+v", metricFamily.GetName(), item)
			items = append(items, item)
		}
	}

	return items
}

func (m *MetricsProvider) getAcquisitionMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics(acquisitionMetrics.AcquisitionMetricsNames, labelsMapping{
		"datasource_type": "datasource_type",
		"source":          "source",
	}, "read", "line")
}

func (m *MetricsProvider) getParserMetrics() []*models.MetricsDetailItem {
	items := make([]*models.MetricsDetailItem, 0)

	return items
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

	/* Acquisition metrics */
	/*{"name": "lines_read", "value": 10, "unit": "line", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}*/
	/* Parser metrics */
	/*{"name": "lines_parsed", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}*/

	acquisitionMetrics := m.getAcquisitionMetrics()
	if len(acquisitionMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, acquisitionMetrics...)
	}

	parserMetrics := m.getParserMetrics()
	if len(parserMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, parserMetrics...)
	}

	return &models.AllMetrics{
		LogProcessors: []*models.LogProcessorsMetrics{met},
	}
}

func (m *MetricsProvider) sendMetrics(ctx context.Context, met *models.AllMetrics) {
	defer trace.CatchPanic("crowdsec/MetricsProvider.sendMetrics")

	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, resp, err := m.apic.UsageMetrics.Add(ctxTime, met)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		m.logger.Warnf("timeout sending lp metrics")
	case err != nil && resp != nil && resp.Response.StatusCode == http.StatusNotFound:
		m.logger.Warnf("metrics endpoint not found, older LAPI?")
	case err != nil:
		m.logger.Warnf("failed to send lp metrics: %s", err)
	case resp.Response.StatusCode != http.StatusCreated:
		m.logger.Warnf("failed to send lp metrics: %s", resp.Response.Status)
	default:
		m.logger.Tracef("lp usage metrics sent")
	}
}

func (m *MetricsProvider) Run(ctx context.Context, myTomb *tomb.Tomb) error {
	defer trace.CatchPanic("crowdsec/MetricsProvider.Run")

	if m.interval == time.Duration(0) {
		return nil
	}

	ticker := time.NewTicker(1) // Send on start

	for {
		select {
		case <-ticker.C:
			met := m.metricsPayload()
			m.sendMetrics(ctx, met)
			ticker.Reset(m.interval)
		case <-myTomb.Dying():
			ticker.Stop()
			return nil
		}
	}
}
