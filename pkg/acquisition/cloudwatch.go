//go:build !no_datasource_cloudwatch

package acquisition

import (
	cloudwatchacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*cloudwatchacquisition.Source)(nil)
	_ types.DSNConfigurer   = (*cloudwatchacquisition.Source)(nil)
	_ types.Fetcher         = (*cloudwatchacquisition.Source)(nil)
	_ types.Tailer          = (*cloudwatchacquisition.Source)(nil)
	_ types.MetricsProvider = (*cloudwatchacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("cloudwatch", func() types.DataSource { return &cloudwatchacquisition.Source{} })
}
