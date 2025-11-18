//go:build !no_datasource_victorialogs

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
)

var (
	// verify interface compliance
	_ DataSource      = (*victorialogs.Source)(nil)
	_ DSNConfigurer   = (*victorialogs.Source)(nil)
	_ Fetcher         = (*victorialogs.Source)(nil)
	_ Tailer          = (*victorialogs.Source)(nil)
	_ MetricsProvider = (*victorialogs.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("victorialogs", func() DataSource { return &victorialogs.Source{} })
}
