//go:build !no_datasource_k8s_podlogs

package metrics

import "github.com/prometheus/client_golang/prometheus"

const K8SPodLogsLinesMetricName = "cs_k8spodlogs_lines_total"

var K8SPodLogsLines = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: K8SPodLogsLinesMetricName,
		Help: "Total lines collected by the Kubernetes pod logs datasource.",
	},
	[]string{"source", "datasource_type", "acquis_type"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(K8SPodLogsLinesMetricName)
}
