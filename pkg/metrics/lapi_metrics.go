package metrics

import "github.com/prometheus/client_golang/prometheus"

/*prometheus*/
var LapiRouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_route_requests_total",
		Help: "Number of calls to each route per method.",
	},
	[]string{"route", "method"},
)

/*hits per machine*/
var LapiMachineHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_machine_requests_total",
		Help: "Number of calls to each route per method grouped by machines.",
	},
	[]string{"machine", "route", "method"},
)

/*hits per bouncer*/
var LapiBouncerHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_bouncer_requests_total",
		Help: "Number of calls to each route per method grouped by bouncers.",
	},
	[]string{"bouncer", "route", "method"},
)

/*
	keep track of the number of calls (per bouncer) that lead to nil/non-nil responses.

while it's not exact, it's a good way to know - when you have a rutpure bouncer - what is the rate of ok/ko answers you got from lapi
*/
var LapiNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_decisions_ko_total",
		Help: "Number of calls to /decisions that returned nil result.",
	},
	[]string{"bouncer"},
)

/*hits per bouncer*/
var LapiNonNilDecisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_lapi_decisions_ok_total",
		Help: "Number of calls to /decisions that returned non-nil result.",
	},
	[]string{"bouncer"},
)

var LapiResponseTime = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cs_lapi_request_duration_seconds",
		Help:    "Response time of LAPI",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.2, 0.3, 0.4, 0.5, 0.75, 1},
	},
	[]string{"endpoint", "method"},
)
