//go:build !no_datasource_loki

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const LokiDataSourceLinesReadMetricName = "cs_lokisource_hits_total"

var LokiDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LokiDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(LokiDataSourceLinesReadMetricName)
}
