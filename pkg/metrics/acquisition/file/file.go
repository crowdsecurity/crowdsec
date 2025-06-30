//go:build !no_datasource_file

package file_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const FileDatasourceLinesReadMetricName = "cs_filesource_hits_total"

var FileDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: FileDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "label_type"},
)

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(FileDatasourceLinesReadMetricName)
}
