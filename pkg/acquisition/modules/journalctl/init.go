package journalctlacquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource          = (*Source)(nil)
	_ types.DSNConfigurer       = (*Source)(nil)
	_ types.BatchFetcher        = (*Source)(nil)
	_ types.RestartableStreamer = (*Source)(nil)
	_ types.MetricsProvider     = (*Source)(nil)
)

const ModuleName = "journalctl"

//nolint:gochecknoinits
func init() {
	registry.RegisterFactory(ModuleName, func() types.DataSource { return &Source{} })
}
