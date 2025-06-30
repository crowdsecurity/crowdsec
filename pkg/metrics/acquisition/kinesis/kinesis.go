//go:build !no_datasource_kinesis

package kinesis_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const KinesisDataSourceLinesReadMetricName = "cs_kinesis_stream_hits_total"

var KinesisDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KinesisDataSourceLinesReadMetricName,
		Help: "Number of event read per stream.",
	},
	[]string{"stream", "datasource_type"},
)

const KinesisDataSourceLinesReadShardsMetricName = "cs_kinesis_shards_hits_total"

var KinesisDataSourceLinesReadShards = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KinesisDataSourceLinesReadShardsMetricName,
		Help: "Number of event read per shards.",
	},
	[]string{"stream", "shard"},
)

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(KinesisDataSourceLinesReadMetricName)
}
