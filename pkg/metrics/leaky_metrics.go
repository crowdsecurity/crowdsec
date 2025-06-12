package metrics

import "github.com/prometheus/client_golang/prometheus"

const BucketPouredMetricName = "cs_bucket_poured_total"

var BucketsPour = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: BucketPouredMetricName,
		Help: "Total events were poured in bucket.",
	},
	[]string{"source", "type", "name"},
)

const BucketsOverflowMetricName = "cs_bucket_overflowed_total"

var BucketsOverflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: BucketsOverflowMetricName,
		Help: "Total buckets overflowed.",
	},
	[]string{"name"},
)

const BucketsCanceledMetricName = "cs_bucket_canceled_total"

var BucketsCanceled = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: BucketsCanceledMetricName,
		Help: "Total buckets canceled.",
	},
	[]string{"name"},
)

const BucketsUnderflowMetricName = "cs_bucket_underflowed_total"

var BucketsUnderflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: BucketsUnderflowMetricName,
		Help: "Total buckets underflowed.",
	},
	[]string{"name"},
)

const BucketsInstantiationMetricName = "cs_bucket_instantiation_total"

var BucketsInstantiation = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: BucketsInstantiationMetricName,
		Help: "Total buckets were instantiated.",
	},
	[]string{"name"},
)

const BucketsCurrentCountMetricName = "cs_buckets"

var BucketsCurrentCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: BucketsCurrentCountMetricName,
		Help: "Number of buckets that currently exist.",
	},
	[]string{"name"},
)
