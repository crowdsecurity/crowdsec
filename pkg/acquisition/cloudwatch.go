//go:build !no_datasource_cloudwatch

package acquisition

import (
	cloudwatchacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch"
)

var (
	// verify interface compliance
	_ DataSource      = (*cloudwatchacquisition.CloudwatchSource)(nil)
	_ DSNConfigurer   = (*cloudwatchacquisition.CloudwatchSource)(nil)
	_ Fetcher         = (*cloudwatchacquisition.CloudwatchSource)(nil)
	_ Tailer          = (*cloudwatchacquisition.CloudwatchSource)(nil)
	_ MetricsProvider = (*cloudwatchacquisition.CloudwatchSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("cloudwatch", func() DataSource { return &cloudwatchacquisition.CloudwatchSource{} })
}
