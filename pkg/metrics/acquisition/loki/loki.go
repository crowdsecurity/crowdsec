package loki_metrics

import "github.com/prometheus/client_golang/prometheus"

const LokiDataSourceLinesReadMetricName = "cs_lokisource_hits_total"

var LokiDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LokiDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source"})
