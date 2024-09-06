// +build !no_datasource_appsec

package acquisition

import (
	appsecacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["appsec"] = func() DataSource { return &appsecacquisition.AppsecSource{} }
}
