package metrics

import "github.com/prometheus/client_golang/prometheus"

const NodesHitsMetricName = "cs_node_hits_total"

var NodesHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: NodesHitsMetricName,
		Help: "Total events entered node.",
	},
	[]string{"source", "type", "name", "stage", "acquis_type"},
)

const NodesHitsOkMetricName = "cs_node_hits_ok_total"

var NodesHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: NodesHitsOkMetricName,
		Help: "Total events successfully exited node.",
	},
	[]string{"source", "type", "name", "stage", "acquis_type"},
)

const NodesHitsKoMetricName = "cs_node_hits_ko_total"

var NodesHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: NodesHitsKoMetricName,
		Help: "Total events unsuccessfully exited node.",
	},
	[]string{"source", "type", "name", "stage", "acquis_type"},
)

const NodesWlHitsOkMetricName = "cs_node_wl_hits_ok_total"

var NodesWlHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: NodesWlHitsOkMetricName,
		Help: "Total events successfully whitelisted by node.",
	},
	[]string{"source", "type", "name", "reason", "stage", "acquis_type"},
)

const NodesWlHitsMetricName = "cs_node_wl_hits_total"

var NodesWlHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: NodesWlHitsMetricName,
		Help: "Total events processed by whitelist node.",
	},
	[]string{"source", "type", "name", "reason", "stage", "acquis_type"},
)
