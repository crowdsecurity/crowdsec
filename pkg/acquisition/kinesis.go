//go:build !no_datasource_kinesis

package acquisition

import (
	kinesisacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kinesis", func() DataSource { return &kinesisacquisition.KinesisSource{} })
}
