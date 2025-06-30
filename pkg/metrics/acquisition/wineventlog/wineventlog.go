//go:build !no_datasource_wineventlog

package wineventlog_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const WineventlogDataSourceLinesReadMetricName = "cs_winevtlogsource_hits_total"

var WineventlogDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: WineventlogDataSourceLinesReadMetricName,
		Help: "Total event that were read.",
	},
	[]string{"source", "datasource_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(WineventlogDataSourceLinesReadMetricName)
}
