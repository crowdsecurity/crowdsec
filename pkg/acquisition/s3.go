//go:build !no_datasource_s3

package acquisition

import (
	s3acquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/s3"
)

var (
	// verify interface compliance
	_ DataSource      = (*s3acquisition.Source)(nil)
	_ DSNConfigurer   = (*s3acquisition.Source)(nil)
	_ Fetcher         = (*s3acquisition.Source)(nil)
	_ Tailer          = (*s3acquisition.Source)(nil)
	_ MetricsProvider = (*s3acquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("s3", func() DataSource { return &s3acquisition.Source{} })
}
