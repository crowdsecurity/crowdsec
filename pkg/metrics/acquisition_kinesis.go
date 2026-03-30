//go:build !no_datasource_kinesis

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const KinesisDataSourceLinesReadMetricName = "cs_kinesis_stream_hits_total"

var KinesisDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KinesisDataSourceLinesReadMetricName,
		Help: "Number of events read per stream.",
	},
	[]string{"stream", "datasource_type", "acquis_type"},
)

const KinesisDataSourceLinesReadShardsMetricName = "cs_kinesis_shards_hits_total"

var KinesisDataSourceLinesReadShards = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KinesisDataSourceLinesReadShardsMetricName,
		Help: "Number of events read per shard.",
	},
	[]string{"stream", "shard"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(KinesisDataSourceLinesReadMetricName)
}
