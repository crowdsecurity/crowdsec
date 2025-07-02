//go:build !no_datasource_s3

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const S3DataSourceLinesReadMetricName = "cs_s3_hits_total"

var S3DataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: S3DataSourceLinesReadMetricName,
		Help: "Number of events read per bucket.",
	},
	[]string{"bucket", "datasource_type", "acquis_type"},
)

const S3DataSourceObjectsReadMetricName = "cs_s3_objects_total"

var S3DataSourceObjectsRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: S3DataSourceObjectsReadMetricName,
		Help: "Number of objects read per bucket.",
	},
	[]string{"bucket"},
)

const S3DataSourceSQSMessagesReceivedMetricName = "cs_s3_sqs_messages_total"

var S3DataSourceSQSMessagesReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: S3DataSourceSQSMessagesReceivedMetricName,
		Help: "Number of SQS messages received per queue.",
	},
	[]string{"queue"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(S3DataSourceLinesReadMetricName)
}
