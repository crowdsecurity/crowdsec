//go:build !no_datasource_http

package acquisition

import (
	httpacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/http"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*httpacquisition.Source)(nil)
	_ types.Tailer          = (*httpacquisition.Source)(nil)
	_ types.MetricsProvider = (*httpacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterDataSource("http", func() types.DataSource { return &httpacquisition.Source{} })
}
