//go:build !no_datasource_journalctl

package acquisition

import (
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource          = (*journalctlacquisition.Source)(nil)
	_ types.DSNConfigurer       = (*journalctlacquisition.Source)(nil)
	_ types.BatchFetcher        = (*journalctlacquisition.Source)(nil)
	_ types.RestartableStreamer = (*journalctlacquisition.Source)(nil)
	_ types.MetricsProvider     = (*journalctlacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("journalctl", func() types.DataSource { return &journalctlacquisition.Source{} })
}
