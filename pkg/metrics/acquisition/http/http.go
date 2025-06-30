//go:build !no_datasource_http

package http_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const HTTPDataSourceLinesReadMetricName = "cs_httpsource_hits_total"

var HTTPDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: HTTPDataSourceLinesReadMetricName,
		Help: "Total lines that were read from http source",
	},
	[]string{"path", "src", "datasource_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(HTTPDataSourceLinesReadMetricName)
}
