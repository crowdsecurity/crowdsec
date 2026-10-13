package metrics

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

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

func MachineIDsWithSeries() []string {
	return labelValues("machine", LapiMachineHits, GlobalMachinesLastHeartbeatTimestamp)
}

func BouncerNamesWithSeries() []string {
	return labelValues("bouncer", LapiBouncerHits, LapiNilDecisions, LapiNonNilDecisions)
}

func DeleteMachineSeries(machineID string) {
	LapiMachineHits.DeletePartialMatch(prometheus.Labels{"machine": machineID})
	GlobalMachinesLastHeartbeatTimestamp.DeleteLabelValues(machineID)
}

func DeleteBouncerSeries(name string) {
	LapiBouncerHits.DeletePartialMatch(prometheus.Labels{"bouncer": name})
	LapiNilDecisions.DeleteLabelValues(name)
	LapiNonNilDecisions.DeleteLabelValues(name)
}

func labelValues(label string, collectors ...prometheus.Collector) []string {
	ch := make(chan prometheus.Metric)

	go func() {
		for _, c := range collectors {
			c.Collect(ch)
		}

		close(ch)
	}()

	seen := map[string]struct{}{}

	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			continue
		}

		for _, lp := range pb.GetLabel() {
			if lp.GetName() == label {
				seen[lp.GetValue()] = struct{}{}
			}
		}
	}

	return slices.Sorted(maps.Keys(seen))
}
