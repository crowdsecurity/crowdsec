//go:build !no_datasource_kinesis

package acquisition

import (
	kinesisacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*kinesisacquisition.Source)(nil)
	_ types.Tailer          = (*kinesisacquisition.Source)(nil)
	_ types.MetricsProvider = (*kinesisacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("kinesis", func() types.DataSource { return &kinesisacquisition.Source{} })
}
