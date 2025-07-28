//go:build !no_datasource_k8saudit

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const K8SAuditDataSourceEventCountMetricName = "cs_k8sauditsource_hits_total"

var K8SAuditDataSourceEventCount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: K8SAuditDataSourceEventCountMetricName,
		Help: "Total number of events received by k8s-audit source",
	},
	[]string{"source", "datasource_type", "acquis_type"})

const K8SAuditDataSourceRequestCountMetricName = "cs_k8sauditsource_requests_total"

var K8SAuditDataSourceRequestCount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: K8SAuditDataSourceRequestCountMetricName,
		Help: "Total number of requests received",
	},
	[]string{"source"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(K8SAuditDataSourceEventCountMetricName)
}
