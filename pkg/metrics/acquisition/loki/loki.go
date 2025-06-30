//go:build !no_datasource_loki

package loki_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const LokiDataSourceLinesReadMetricName = "cs_lokisource_hits_total"

var LokiDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LokiDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "label_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(LokiDataSourceLinesReadMetricName)
}
