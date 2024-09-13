//go:build !no_datasource_kafka

package acquisition

import (
	kafkaacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kafka", func() DataSource { return &kafkaacquisition.KafkaSource{} })
}
