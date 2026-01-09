//go:build !no_datasource_victorialogs

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*victorialogs.Source)(nil)
	_ types.DSNConfigurer   = (*victorialogs.Source)(nil)
	_ types.Fetcher         = (*victorialogs.Source)(nil)
	_ types.Tailer          = (*victorialogs.Source)(nil)
	_ types.MetricsProvider = (*victorialogs.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterDataSource("victorialogs", func() types.DataSource { return &victorialogs.Source{} })
}
