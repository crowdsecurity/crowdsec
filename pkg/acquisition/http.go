//go:build !no_datasource_http

package acquisition

import (
	httpacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/http"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("http", func() DataSource { return &httpacquisition.HTTPSource{} })
}
