package metrics

import "github.com/prometheus/client_golang/prometheus"

const RegexpCacheMetricName = "cs_regexp_cache_size"

var RegexpCacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: RegexpCacheMetricName,
		Help: "Entries per regexp cache.",
	},
	[]string{"name"},
)
