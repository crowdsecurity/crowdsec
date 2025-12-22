//go:build !no_datasource_file

package acquisition

import (
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
)

var (
	// verify interface compliance
	_ DataSource      = (*fileacquisition.Source)(nil)
	_ DSNConfigurer   = (*fileacquisition.Source)(nil)
	_ BatchFetcher    = (*fileacquisition.Source)(nil)
	_ Tailer          = (*fileacquisition.Source)(nil)
	_ MetricsProvider = (*fileacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("file", func() DataSource { return &fileacquisition.Source{} })
}
