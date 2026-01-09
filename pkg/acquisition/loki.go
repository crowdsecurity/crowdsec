//go:build !no_datasource_loki

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*loki.Source)(nil)
	_ types.DSNConfigurer   = (*loki.Source)(nil)
	_ types.Fetcher         = (*loki.Source)(nil)
	_ types.Tailer          = (*loki.Source)(nil)
	_ types.MetricsProvider = (*loki.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("loki", func() types.DataSource { return &loki.Source{} })
}
