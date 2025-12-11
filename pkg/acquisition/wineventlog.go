//go:build !no_datasource_wineventlog

package acquisition

import (
	wineventlogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog"
)

var (
	// verify interface compliance
	_ DataSource      = (*wineventlogacquisition.Source)(nil)
	_ DSNConfigurer   = (*wineventlogacquisition.Source)(nil)
	_ BatchFetcher    = (*wineventlogacquisition.Source)(nil)
	_ Tailer          = (*wineventlogacquisition.Source)(nil)
	_ MetricsProvider = (*wineventlogacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("wineventlog", func() DataSource { return &wineventlogacquisition.Source{} })
}
