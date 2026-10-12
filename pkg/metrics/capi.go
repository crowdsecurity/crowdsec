package metrics

import "github.com/prometheus/client_golang/prometheus"

const CapiLastPullTimestampMetricName = "cs_capi_last_pull_timestamp"

var CapiLastPullTimestamp = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: CapiLastPullTimestampMetricName,
		Help: "Unix timestamp of the last successful decisions stream pull from the CAPI.",
	},
)

const CapiErrorsMetricName = "cs_capi_errors_total"

var CapiErrors = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: CapiErrorsMetricName,
		Help: "Number of failed requests to the CAPI.",
	},
	[]string{"operation"},
)

// values of the "operation" label of CapiErrors
const (
	CapiOperationPull    = "pull"
	CapiOperationPush    = "push"
	CapiOperationMetrics = "metrics"
)
