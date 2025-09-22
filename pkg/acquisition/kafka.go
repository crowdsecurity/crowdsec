//go:build !no_datasource_kafka

package acquisition

import (
	kafkaacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka"
)

var (
	// verify interface compliance
	_ DataSource      = (*kafkaacquisition.KafkaSource)(nil)
	_ Tailer          = (*kafkaacquisition.KafkaSource)(nil)
	_ MetricsProvider = (*kafkaacquisition.KafkaSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kafka", func() DataSource { return &kafkaacquisition.KafkaSource{} })
}
