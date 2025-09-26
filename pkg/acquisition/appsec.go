//go:build !no_datasource_appsec

package acquisition

import (
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
)

var (
	// verify interface compliance
	_ DataSource      = (*appsecacquisition.AppsecSource)(nil)
	_ Tailer          = (*appsecacquisition.AppsecSource)(nil)
	_ MetricsProvider = (*appsecacquisition.AppsecSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("appsec", func() DataSource { return &appsecacquisition.AppsecSource{} })
}
