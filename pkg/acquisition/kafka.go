//go:build !no_datasource_kafka

package acquisition

import (
	kafkaacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*kafkaacquisition.Source)(nil)
	_ types.Tailer          = (*kafkaacquisition.Source)(nil)
	_ types.MetricsProvider = (*kafkaacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kafka", func() types.DataSource { return &kafkaacquisition.Source{} })
}
