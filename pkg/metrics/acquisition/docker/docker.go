//go:build !no_datasource_docker

package docker_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const DockerDatasourceLinesReadMetricName = "cs_dockersource_hits_total"

var DockerDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: DockerDatasourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "label_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(DockerDatasourceLinesReadMetricName)
}
