//go:build !no_datasource_loki

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
)

var (
	// verify interface compliance
	_ DataSource      = (*loki.Source)(nil)
	_ DSNConfigurer   = (*loki.Source)(nil)
	_ Fetcher         = (*loki.Source)(nil)
	_ Tailer          = (*loki.Source)(nil)
	_ MetricsProvider = (*loki.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("loki", func() DataSource { return &loki.Source{} })
}
