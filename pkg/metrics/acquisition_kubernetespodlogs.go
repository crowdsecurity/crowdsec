//go:build !no_datasource_kubernetespodlogs

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const KubernetesPodLogsDataSourceLinesReadMetricName = "cs_kubernetespodlogssource_hits_total"

var KubernetesPodLogsDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KubernetesPodLogsDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(KubernetesPodLogsDataSourceLinesReadMetricName)
}
