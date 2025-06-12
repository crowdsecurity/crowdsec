package wineventlog_metrics

import "github.com/prometheus/client_golang/prometheus"

const WineventlogDataSourceLinesReadMetricName = "cs_winevtlogsource_hits_total"

var WineventlogDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: WineventlogDataSourceLinesReadMetricName,
		Help: "Total event that were read.",
	},
	[]string{"source"})
