package metrics

import "github.com/prometheus/client_golang/prometheus"

var NodesHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_total",
		Help: "Total events entered node.",
	},
	[]string{"source", "type", "name"},
)

var NodesHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_ok_total",
		Help: "Total events successfully exited node.",
	},
	[]string{"source", "type", "name"},
)

var NodesHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_ko_total",
		Help: "Total events unsuccessfully exited node.",
	},
	[]string{"source", "type", "name"},
)

//

var NodesWlHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_wl_hits_ok_total",
		Help: "Total events successfully whitelisted by node.",
	},
	[]string{"source", "type", "name", "reason"},
)

var NodesWlHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_wl_hits_total",
		Help: "Total events processed by whitelist node.",
	},
	[]string{"source", "type", "name", "reason"},
)
