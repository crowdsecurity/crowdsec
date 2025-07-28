package metrics

import "github.com/prometheus/client_golang/prometheus"

const LapiRouteHitsMetricName = "cs_lapi_route_requests_total"

var LapiRouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LapiRouteHitsMetricName,
		Help: "Number of calls to each route per method.",
	},
	[]string{"route", "method"},
)

/*hits per machine*/
const LapiMachineHitsMetricName = "cs_lapi_machine_requests_total"

var LapiMachineHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LapiMachineHitsMetricName,
		Help: "Number of calls to each route per method grouped by machines.",
	},
	[]string{"machine", "route", "method"},
)

/*hits per bouncer*/
const LapiBouncerHitsMetricName = "cs_lapi_bouncer_requests_total"

var LapiBouncerHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LapiBouncerHitsMetricName,
		Help: "Number of calls to each route per method grouped by bouncers.",
	},
	[]string{"bouncer", "route", "method"},
)

/*
	keep track of the number of calls (per bouncer) that lead to nil/non-nil responses.

while it's not exact, it's a good way to know - when you have a rutpure bouncer - what is the rate of ok/ko answers you got from lapi
*/
const LapiNilDecisionsMetricName = "cs_lapi_decisions_ko_total"

var LapiNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LapiNilDecisionsMetricName,
		Help: "Number of calls to /decisions that returned nil result.",
	},
	[]string{"bouncer"},
)

/*hits per bouncer*/
const LapiNonNilDecisionsMetricName = "cs_lapi_decisions_ok_total"

var LapiNonNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: LapiNonNilDecisionsMetricName,
		Help: "Number of calls to /decisions that returned non-nil result.",
	},
	[]string{"bouncer"},
)

const LapiResponseTimeMetricName = "cs_lapi_request_duration_seconds"

var LapiResponseTime = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    LapiResponseTimeMetricName,
		Help:    "Response time of LAPI",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.2, 0.3, 0.4, 0.5, 0.75, 1},
	},
	[]string{"endpoint", "method"},
)
