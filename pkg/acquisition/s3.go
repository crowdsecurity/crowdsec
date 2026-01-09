//go:build !no_datasource_s3

package acquisition

import (
	s3acquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/s3"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*s3acquisition.Source)(nil)
	_ types.DSNConfigurer   = (*s3acquisition.Source)(nil)
	_ types.Fetcher         = (*s3acquisition.Source)(nil)
	_ types.Tailer          = (*s3acquisition.Source)(nil)
	_ types.MetricsProvider = (*s3acquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("s3", func() types.DataSource { return &s3acquisition.Source{} })
}
