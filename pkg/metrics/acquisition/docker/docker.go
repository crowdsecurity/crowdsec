package docker_metrics

import "github.com/prometheus/client_golang/prometheus"

const DockerDatasourceLinesReadMetricName = "cs_dockersource_hits_total"

var DockerDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: DockerDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source"})
