package parser

import (
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

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

var NodesHitsWl = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_wl_total",
		Help: "Total events entered whitelists.",
	},
	[]string{"name", "source", "type"},
)

var NodesHitsWlOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_wl_ok_total",
		Help: "Total events successfully exited node.",
	},
	[]string{"name", "expression", "source", "type"},
)

var NodesHitsWlKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_wl_ko_total",
		Help: "Total events unsuccessfully exited node.",
	},
	[]string{"name", "expression", "source", "type"},
)

// Increase the number of hits for a node excluding whitelists
func (n *Node) IncPromHits(p *types.Event) {
	if n.Name == "" {
		return
	}
	if !n.ContainsWLs() {
		NodesHits.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
	}
}

// Increase the number of ok hits for a node excluding whitelists
func (n *Node) IncOkNodeHits(p *types.Event) {
	if n.Name == "" || n.ContainsWLs() {
		return
	}
	NodesHitsOk.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
}

// Increase the number of ko hits for a node excluding whitelists
func (n *Node) IncKoNodeHits(p *types.Event) {
	if n.Name == "" || n.ContainsWLs() {
		return
	}
	NodesHitsKo.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
}

// Increase the number of ok hits for a whitelist node
func (n *Node) IncOkWLHits(p *types.Event, expr string) {
	if n.Name == "" || !n.ContainsWLs() {
		return
	}
	NodesHitsWlOk.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name, "expression": expr}).Inc()
}

// Increase the number of ko hits for a whitelist node
func (n *Node) IncKoWLHits(p *types.Event, expr string) {
	if n.Name == "" || !n.ContainsWLs() {
		return
	}
	NodesHitsWlKo.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name, "expression": expr}).Inc()
}
