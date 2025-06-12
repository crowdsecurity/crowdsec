package victorialogs_metrics

import "github.com/prometheus/client_golang/prometheus"

const VictorialogsDataSourceLinesReadMetricName = "cs_victorialogssource_hits_total"

var VictorialogsDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: VictorialogsDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source"})
