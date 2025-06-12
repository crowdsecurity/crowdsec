package metrics

import "github.com/prometheus/client_golang/prometheus"

var BucketsPour = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_poured_total",
		Help: "Total events were poured in bucket.",
	},
	[]string{"source", "type", "name"},
)

var BucketsOverflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_overflowed_total",
		Help: "Total buckets overflowed.",
	},
	[]string{"name"},
)

var BucketsCanceled = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_canceled_total",
		Help: "Total buckets canceled.",
	},
	[]string{"name"},
)

var BucketsUnderflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_underflowed_total",
		Help: "Total buckets underflowed.",
	},
	[]string{"name"},
)

var BucketsInstantiation = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_created_total",
		Help: "Total buckets were instantiated.",
	},
	[]string{"name"},
)

var BucketsCurrentCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_buckets",
		Help: "Number of buckets that currently exist.",
	},
	[]string{"name"},
)
