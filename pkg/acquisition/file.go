//go:build !no_datasource_file

package acquisition

import (
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*fileacquisition.Source)(nil)
	_ types.DSNConfigurer   = (*fileacquisition.Source)(nil)
	_ types.BatchFetcher    = (*fileacquisition.Source)(nil)
	_ types.Tailer          = (*fileacquisition.Source)(nil)
	_ types.MetricsProvider = (*fileacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("file", func() types.DataSource { return &fileacquisition.Source{} })
}
