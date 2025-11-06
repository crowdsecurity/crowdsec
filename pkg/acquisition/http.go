//go:build !no_datasource_http

package acquisition

import (
	httpacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/http"
)

var (
	// verify interface compliance
	_ DataSource      = (*httpacquisition.Source)(nil)
	_ Tailer          = (*httpacquisition.Source)(nil)
	_ MetricsProvider = (*httpacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("http", func() DataSource { return &httpacquisition.Source{} })
}
