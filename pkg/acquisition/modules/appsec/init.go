package appsecacquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*Source)(nil)
	_ types.Tailer          = (*Source)(nil)
	_ types.MetricsProvider = (*Source)(nil)
	_ types.HubAware        = (*Source)(nil)
	_ types.LAPIClientAware = (*Source)(nil)
)

const ModuleName = appsec.ModuleName

//nolint:gochecknoinits
func init() {
	registry.RegisterFactory(ModuleName, func() types.DataSource { return &Source{} })
}
