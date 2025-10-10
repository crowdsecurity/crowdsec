//go:build !no_datasource_file

package acquisition

import (
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
)

var (
	// verify interface compliance
	_ DataSource      = (*fileacquisition.FileSource)(nil)
	_ DSNConfigurer   = (*fileacquisition.FileSource)(nil)
	_ Fetcher         = (*fileacquisition.FileSource)(nil)
	_ Tailer          = (*fileacquisition.FileSource)(nil)
	_ MetricsProvider = (*fileacquisition.FileSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("file", func() DataSource { return &fileacquisition.FileSource{} })
}
