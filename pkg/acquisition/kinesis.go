//go:build !no_datasource_kinesis

package acquisition

import (
	kinesisacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis"
)

var (
	// verify interface compliance
	_ DataSource      = (*kinesisacquisition.Source)(nil)
	_ Tailer          = (*kinesisacquisition.Source)(nil)
	_ MetricsProvider = (*kinesisacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kinesis", func() DataSource { return &kinesisacquisition.Source{} })
}
