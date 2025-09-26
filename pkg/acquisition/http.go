//go:build !no_datasource_http

package acquisition

import (
	httpacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/http"
)

var (
	// verify interface compliance
	_ DataSource      = (*httpacquisition.HTTPSource)(nil)
	_ Tailer          = (*httpacquisition.HTTPSource)(nil)
	_ MetricsProvider = (*httpacquisition.HTTPSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("http", func() DataSource { return &httpacquisition.HTTPSource{} })
}
