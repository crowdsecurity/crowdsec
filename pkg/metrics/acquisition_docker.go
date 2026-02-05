//go:build !no_datasource_docker

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const DockerDatasourceLinesReadMetricName = "cs_dockersource_hits_total"

var DockerDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: DockerDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(DockerDatasourceLinesReadMetricName)
}
