//go:build !no_datasource_kafka

package kafka_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const KafkaDataSourceLinesReadMetricName = "cs_kafkasource_hits_total"

var KafkaDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KafkaDataSourceLinesReadMetricName,
		Help: "Total lines that were read from topic",
	},
	[]string{"topic", "datasource_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(KafkaDataSourceLinesReadMetricName)
}
