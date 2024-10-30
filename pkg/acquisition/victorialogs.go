//go:build !no_datasource_victorialogs

package acquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("victorialogs", func() DataSource { return &victorialogs.VLSource{} })
}
