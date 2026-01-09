//go:build !no_datasource_wineventlog

package acquisition

import (
	wineventlogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*wineventlogacquisition.Source)(nil)
	_ types.DSNConfigurer   = (*wineventlogacquisition.Source)(nil)
	_ types.BatchFetcher    = (*wineventlogacquisition.Source)(nil)
	_ types.Tailer          = (*wineventlogacquisition.Source)(nil)
	_ types.MetricsProvider = (*wineventlogacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("wineventlog", func() types.DataSource { return &wineventlogacquisition.Source{} })
}
