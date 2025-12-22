//go:build !no_datasource_journalctl

package acquisition

import (
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
)

var (
	// verify interface compliance
	_ DataSource          = (*journalctlacquisition.Source)(nil)
	_ DSNConfigurer       = (*journalctlacquisition.Source)(nil)
	_ BatchFetcher        = (*journalctlacquisition.Source)(nil)
	_ RestartableStreamer = (*journalctlacquisition.Source)(nil)
	_ MetricsProvider     = (*journalctlacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("journalctl", func() DataSource { return &journalctlacquisition.Source{} })
}
