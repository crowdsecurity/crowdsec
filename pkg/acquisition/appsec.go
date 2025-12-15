//go:build !no_datasource_appsec

package acquisition

import (
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
)

var (
	// verify interface compliance
	_ DataSource      = (*appsecacquisition.Source)(nil)
	_ Tailer          = (*appsecacquisition.Source)(nil)
	_ MetricsProvider = (*appsecacquisition.Source)(nil)
	_ HubAware        = (*appsecacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("appsec", func() DataSource { return &appsecacquisition.Source{} })
}
