package appsecacquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*Source)(nil)
	_ types.Tailer          = (*Source)(nil)
	_ types.MetricsProvider = (*Source)(nil)
	_ types.HubAware        = (*Source)(nil)
	_ types.LAPIClientAware = (*Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterFactory("appsec", func() types.DataSource { return &Source{} })
}
