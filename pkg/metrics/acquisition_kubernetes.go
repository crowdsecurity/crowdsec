//go:build !no_datasource_kubernetes

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const KubernetesDataSourceLinesReadMetricName = "cs_kubernetessource_hits_total"

var KubernetesDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KubernetesDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(KubernetesDataSourceLinesReadMetricName)
}
