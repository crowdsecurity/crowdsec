//go:build !no_datasource_cloudwatch

package acquisition

import (
	cloudwatchacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch"
)

var (
	// verify interface compliance
	_ DataSource      = (*cloudwatchacquisition.Source)(nil)
	_ DSNConfigurer   = (*cloudwatchacquisition.Source)(nil)
	_ Fetcher         = (*cloudwatchacquisition.Source)(nil)
	_ Tailer          = (*cloudwatchacquisition.Source)(nil)
	_ MetricsProvider = (*cloudwatchacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("cloudwatch", func() DataSource { return &cloudwatchacquisition.Source{} })
}
