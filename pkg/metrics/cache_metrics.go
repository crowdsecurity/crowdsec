package metrics

import "github.com/prometheus/client_golang/prometheus"

var CacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_cache_size",
		Help: "Entries per cache.",
	},
	[]string{"name", "type"},
)
