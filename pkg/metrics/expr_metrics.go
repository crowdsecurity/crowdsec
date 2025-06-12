package metrics

import "github.com/prometheus/client_golang/prometheus"

var RegexpCacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_regexp_cache_size",
		Help: "Entries per regexp cache.",
	},
	[]string{"name"},
)
