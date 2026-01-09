//go:build !no_datasource_appsec

package acquisition

import (
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*appsecacquisition.Source)(nil)
	_ types.Tailer          = (*appsecacquisition.Source)(nil)
	_ types.MetricsProvider = (*appsecacquisition.Source)(nil)
	_ types.HubAware        = (*appsecacquisition.Source)(nil)
	_ types.LAPIClientAware = (*appsecacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("appsec", func() types.DataSource { return &appsecacquisition.Source{} })
}
