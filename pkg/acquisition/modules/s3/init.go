package s3acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*Source)(nil)
	_ types.DSNConfigurer   = (*Source)(nil)
	_ types.Fetcher         = (*Source)(nil)
	_ types.Tailer          = (*Source)(nil)
	_ types.MetricsProvider = (*Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterDataSource("s3", func() types.DataSource { return &Source{} })
}
