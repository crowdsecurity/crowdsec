//go:build !no_datasource_appsec

package acquisition

import (
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("appsec", func() DataSource { return &appsecacquisition.AppsecSource{} })
}
