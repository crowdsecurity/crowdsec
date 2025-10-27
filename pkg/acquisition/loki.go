//go:build !no_datasource_loki

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
)

var (
	// verify interface compliance
	_ DataSource      = (*loki.LokiSource)(nil)
	_ DSNConfigurer   = (*loki.LokiSource)(nil)
	_ Fetcher         = (*loki.LokiSource)(nil)
	_ Tailer          = (*loki.LokiSource)(nil)
	_ MetricsProvider = (*loki.LokiSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("loki", func() DataSource { return &loki.LokiSource{} })
}
