//go:build !no_datasource_http

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const HTTPDataSourceLinesReadMetricName = "cs_httpsource_hits_total"

var HTTPDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: HTTPDataSourceLinesReadMetricName,
		Help: "Total lines that were read from http source",
	},
	[]string{"path", "src", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(HTTPDataSourceLinesReadMetricName)
}
