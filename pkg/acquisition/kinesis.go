//go:build !no_datasource_kinesis

package acquisition

import (
	kinesisacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis"
)

var (
	// verify interface compliance
	_ DataSource      = (*kinesisacquisition.KinesisSource)(nil)
	_ Tailer          = (*kinesisacquisition.KinesisSource)(nil)
	_ MetricsProvider = (*kinesisacquisition.KinesisSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kinesis", func() DataSource { return &kinesisacquisition.KinesisSource{} })
}
