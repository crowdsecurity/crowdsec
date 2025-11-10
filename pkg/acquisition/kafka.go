//go:build !no_datasource_kafka

package acquisition

import (
	kafkaacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka"
)

var (
	// verify interface compliance
	_ DataSource      = (*kafkaacquisition.Source)(nil)
	_ Tailer          = (*kafkaacquisition.Source)(nil)
	_ MetricsProvider = (*kafkaacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kafka", func() DataSource { return &kafkaacquisition.Source{} })
}
