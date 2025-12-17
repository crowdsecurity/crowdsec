//go:build !no_datasource_cloudwatch

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const CloudWatchDatasourceOpenedStreamsMetricName = "cs_cloudwatch_openstreams_total"

var CloudWatchDatasourceOpenedStreams = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: CloudWatchDatasourceOpenedStreamsMetricName,
		Help: "Number of opened stream within group.",
	},
	[]string{"group"},
)

const CloudWatchDatasourceLinesReadMetricName = "cs_cloudwatch_stream_hits_total"

var CloudWatchDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: CloudWatchDatasourceLinesReadMetricName,
		Help: "Number of events read from stream.",
	},
	[]string{"group", "stream", "datasource_type", "acquis_type"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(CloudWatchDatasourceLinesReadMetricName)
}
