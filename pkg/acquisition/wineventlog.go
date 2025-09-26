//go:build !no_datasource_wineventlog

package acquisition

import (
	wineventlogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog"
)

var (
	// verify interface compliance
	_ DataSource      = (*wineventlogacquisition.WinEventLogSource)(nil)
	_ DSNConfigurer   = (*wineventlogacquisition.WinEventLogSource)(nil)
	_ Fetcher         = (*wineventlogacquisition.WinEventLogSource)(nil)
	_ Tailer          = (*wineventlogacquisition.WinEventLogSource)(nil)
	_ MetricsProvider = (*wineventlogacquisition.WinEventLogSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("wineventlog", func() DataSource { return &wineventlogacquisition.WinEventLogSource{} })
}
