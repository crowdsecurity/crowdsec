//go:build !no_datasource_file

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const FileDatasourceLinesReadMetricName = "cs_filesource_hits_total"

var FileDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: FileDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "acquis_type"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(FileDatasourceLinesReadMetricName)
}
