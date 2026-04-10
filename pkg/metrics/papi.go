package metrics

import "github.com/prometheus/client_golang/prometheus"

const PapiOrdersReceivedMetricName = "cs_papi_orders_received_total"

var PapiOrdersReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: PapiOrdersReceivedMetricName,
		Help: "Number of orders received by papi.",
	},
	[]string{"type", "command"},
)

const PapiInvalidOrdersReceivedMetricName = "cs_papi_invalid_orders_received_total"

var PapiInvalidOrdersReceived = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: PapiInvalidOrdersReceivedMetricName,
		Help: "Number of invalid orders received by papi.",
	},
)

const PapiLastPullTimestampMetricName = "cs_papi_last_pull_timestamp"

var PapiLastPullTimestamp = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: PapiLastPullTimestampMetricName,
		Help: "Unix timestamp of the last successful PAPI pull.",
	},
)

const PapiPollErrorsMetricName = "cs_papi_poll_errors_total"

var PapiPollErrors = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: PapiPollErrorsMetricName,
		Help: "Number of errors encountered while polling PAPI.",
	},
)
