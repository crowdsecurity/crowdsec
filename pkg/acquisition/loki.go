// +build !no_datasource_loki

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["loki"] = func() DataSource { return &loki.LokiSource{} }
}
