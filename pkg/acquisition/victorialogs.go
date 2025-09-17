//go:build !no_datasource_victorialogs

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
)

var (
	// verify interface compliance
	_ DataSource      = (*victorialogs.VLSource)(nil)
	_ DSNConfigurer   = (*victorialogs.VLSource)(nil)
	_ Fetcher         = (*victorialogs.VLSource)(nil)
	_ Tailer          = (*victorialogs.VLSource)(nil)
	_ MetricsProvider = (*victorialogs.VLSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("victorialogs", func() DataSource { return &victorialogs.VLSource{} })
}
