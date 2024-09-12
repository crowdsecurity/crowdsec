//go:build !no_datasource_wineventlog

package acquisition

import (
	wineventlogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("wineventlog", func() DataSource { return &wineventlogacquisition.WinEventLogSource{} })
}
