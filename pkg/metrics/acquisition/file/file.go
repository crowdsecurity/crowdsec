package file_metrics

import "github.com/prometheus/client_golang/prometheus"

const FileDatasourceLinesReadMetricName = "cs_filesource_hits_total"

var FileDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: FileDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source"},
)
