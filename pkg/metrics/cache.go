package metrics

import "github.com/prometheus/client_golang/prometheus"

const CacheMetricName = "cs_cache_size"

var CacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: CacheMetricName,
		Help: "Entries per cache.",
	},
	[]string{"name", "type"},
)
