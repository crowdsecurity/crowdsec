package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	acquisitionTypes "github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const lpMetricsDefaultInterval = 30 * time.Minute

var childNodeExcludeRegexp = regexp.MustCompile("^child-")

// This is not stored in the metrics provider because it gets recreated during a reload
// Which would make us lose the last values of the metrics, and mess up the delta for the next run because the prometheus metrics themselves are not reset
// There's only a single instance of MetricsProvider, so no need to mutex or anything
// This used to store the last collected value of a metric to compute the delta before sending it
// Key is a concatenation of all labels
var metricsLastValues = make(map[string]float64)

// MetricsProvider collects metrics from the LP and sends them to the LAPI
type MetricsProvider struct {
	apic     *apiclient.ApiClient
	interval time.Duration
	static   staticMetrics
	logger   *logrus.Entry
}

type staticMetrics struct {
	osName         string
	osFamily       string
	osVersion      string
	startupTS      int64
	featureFlags   []string
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
func newStaticMetrics(datasources []acquisitionTypes.DataSource, hub *cwhub.Hub) staticMetrics {
	datasourceMap := map[string]int64{}

	for _, ds := range datasources {
		datasourceMap[ds.GetName()] += 1
	}

	osName, osFamily, osVersion := version.DetectOS()

	return staticMetrics{
		osName:         osName,
		osFamily:       osFamily,
		osVersion:      osVersion,
		startupTS:      time.Now().UTC().Unix(),
		featureFlags:   fflag.Crowdsec.GetEnabledFeatures(),
		datasourceMap:  datasourceMap,
		hubState:       getHubState(hub),
	}
}

func NewMetricsProvider(
	apic *apiclient.ApiClient,
	interval time.Duration,
	logger *logrus.Entry,
	datasources []acquisitionTypes.DataSource,
	hub *cwhub.Hub,
) *MetricsProvider {
	static := newStaticMetrics(datasources, hub)
	
	logger.Debugf("Detected %s %s (family: %s)", static.osName, static.osVersion, static.osFamily)

	return &MetricsProvider{
		apic:     apic,
		interval: interval,
		logger:   logger,
		static:   static,
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

func getDeltaKey(metricName string, labels []*io_prometheus_client.LabelPair) string {
	// Create a key from the labels to use as a map key
	// This is used to store the last value of the metric to compute the delta
	parts := make([]string, 0, len(labels)+1)
	parts = append(parts, metricName)
	sortedLabels := slices.Clone(labels)
	slices.SortFunc(sortedLabels, func(a, b *io_prometheus_client.LabelPair) int {
		return strings.Compare(a.GetName(), b.GetName())
	})

	for _, label := range sortedLabels {
		parts = append(parts, label.GetName()+label.GetValue())
	}

	return strings.Join(parts, "")
}

func shouldIgnoreMetric(exclude map[string]*regexp.Regexp, promLabels []*io_prometheus_client.LabelPair) bool {
	for labelKey, regex := range exclude {
		labelValue := getLabelValue(promLabels, labelKey)
		if labelValue == "" {
			continue
		}

		if regex.MatchString(labelValue) {
			return true
		}
	}

	return false
}

func (m *MetricsProvider) gatherPromMetrics(metricsName []string, labelsMap labelsMapping, exclude map[string]*regexp.Regexp, metricName string, unitType string) []*models.MetricsDetailItem {
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

			if shouldIgnoreMetric(exclude, promLabels) {
				continue
			}

			deltaKey := getDeltaKey(metricFamily.GetName(), promLabels)
			metricsLabels := make(map[string]string)

			for labelKey, labelValue := range labelsMap {
				metricsLabels[labelValue] = getLabelValue(promLabels, labelKey)
			}

			currentValue := metric.GetCounter().GetValue()
			value := currentValue

			if lastValue, ok := metricsLastValues[deltaKey]; ok {
				value -= lastValue
				if value < 0 {
					m.logger.Warnf("negative delta for metric %s (labels: %+v), resetting to 0. This is probably a bug.", metricName, metricsLabels)
					value = 0
				}
			}

			metricsLastValues[deltaKey] = currentValue

			if value == 0 {
				continue
			}

			item := &models.MetricsDetailItem{
				Name:   ptr.Of(metricName),
				Unit:   ptr.Of(unitType),
				Labels: metricsLabels,
				Value:  ptr.Of(value),
			}
			m.logger.Debugf("Gathered metric: %s, item: %+v", metricFamily.GetName(), item)
			items = append(items, item)
		}
	}

	return items
}

func (m *MetricsProvider) getAcquisitionMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics(metrics.AcquisitionMetricsNames, labelsMapping{
		"datasource_type": "datasource_type",
		"source":          "source",
		"acquis_type":     "acquis_type",
	}, nil, "read", "line")
}

func (m *MetricsProvider) getParserGlobalOkMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.GlobalParserHitsOkMetricName}, labelsMapping{
		"type":        "datasource_type",
		"source":      "source",
		"acquis_type": "acquis_type",
	}, nil, "global_parsed", "line")
}

func (m *MetricsProvider) getParserGlobalKoMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.GlobalParserHitsKoMetricName}, labelsMapping{
		"type":        "datasource_type",
		"source":      "source",
		"acquis_type": "acquis_type",
	}, nil, "global_unparsed", "line")
}

func (m *MetricsProvider) getParserSuccessMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.NodesHitsOkMetricName}, labelsMapping{
		"type":        "datasource_type",
		"source":      "source",
		"acquis_type": "acquis_type",
		"name":        "parser_name",
		"stage":       "parser_stage",
	}, map[string]*regexp.Regexp{
		"name": childNodeExcludeRegexp,
	}, "parsed", "line",
	)
}

func (m *MetricsProvider) getParserFailureMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.NodesHitsKoMetricName}, labelsMapping{
		"type":        "datasource_type",
		"source":      "source",
		"acquis_type": "acquis_type",
		"name":        "parser_name",
		"stage":       "parser_stage",
	}, map[string]*regexp.Regexp{
		"name": childNodeExcludeRegexp,
	}, "unparsed", "line",
	)
}

func (m *MetricsProvider) getParserWhitelistMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.NodesWlHitsOkMetricName}, labelsMapping{
		"type":        "datasource_type",
		"source":      "source",
		"acquis_type": "acquis_type",
		"name":        "whitelist_name",
		"stage":       "whitelist_stage",
	}, nil, "whitelisted", "event",
	)
}

func (m *MetricsProvider) getAppsecProcessedMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.AppsecReqCounterMetricName}, labelsMapping{
		"appsec_engine": "appsec_engine",
	}, nil, "appsec_processed", "request")
}

func (m *MetricsProvider) getAppsecBlockedMetrics() []*models.MetricsDetailItem {
	return m.gatherPromMetrics([]string{metrics.AppsecBlockCounterMetricName}, labelsMapping{
		"appsec_engine": "appsec_engine",
	}, nil, "appsec_blocked", "request")
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

	// Acquisition metrics
	// {"name": "read", "value": 10, "unit": "line", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}
	//  Parser metrics
	// {"name": "parsed", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}
	// {"name": "unparsed", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}
	// {"name": "whitelisted", labels: {"datasource_type": "file", "source":"/var/log/auth.log"}}

	acquisitionMetrics := m.getAcquisitionMetrics()
	if len(acquisitionMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, acquisitionMetrics...)
	}

	parserSuccessMetrics := m.getParserSuccessMetrics()
	if len(parserSuccessMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, parserSuccessMetrics...)
	}

	parserFailureMetrics := m.getParserFailureMetrics()
	if len(parserFailureMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, parserFailureMetrics...)
	}

	parserWhitelistMetrics := m.getParserWhitelistMetrics()
	if len(parserWhitelistMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, parserWhitelistMetrics...)
	}

	globalParsedMetrics := m.getParserGlobalOkMetrics()
	if len(globalParsedMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, globalParsedMetrics...)
	}

	globalUnparsedMetrics := m.getParserGlobalKoMetrics()
	if len(globalUnparsedMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, globalUnparsedMetrics...)
	}

	appsecProcessedMetrics := m.getAppsecProcessedMetrics()
	if len(appsecProcessedMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, appsecProcessedMetrics...)
	}

	appsecBlockedMetrics := m.getAppsecBlockedMetrics()
	if len(appsecBlockedMetrics) > 0 {
		met.Metrics[0].Items = append(met.Metrics[0].Items, appsecBlockedMetrics...)
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

func (m *MetricsProvider) Run(ctx context.Context) {
	defer trace.CatchPanic("crowdsec/MetricsProvider.Run")

	if m.interval == time.Duration(0) {
		return
	}

	ticker := time.NewTicker(1) // Send on start

	for {
		select {
		case <-ticker.C:
			met := m.metricsPayload()
			m.sendMetrics(ctx, met)
			ticker.Reset(m.interval)
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
