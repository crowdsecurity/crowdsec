//go:build !no_datasource_kafka

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const KafkaDataSourceLinesReadMetricName = "cs_kafkasource_hits_total"

var KafkaDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: KafkaDataSourceLinesReadMetricName,
		Help: "Total lines that were read from topic",
	},
	[]string{"topic", "datasource_type", "acquis_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(KafkaDataSourceLinesReadMetricName)
}
