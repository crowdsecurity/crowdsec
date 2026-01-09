//go:build !no_datasource_docker

package acquisition

import (
	dockeracquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*dockeracquisition.Source)(nil)
	_ types.DSNConfigurer   = (*dockeracquisition.Source)(nil)
	_ types.Fetcher         = (*dockeracquisition.Source)(nil)
	_ types.Tailer          = (*dockeracquisition.Source)(nil)
	_ types.MetricsProvider = (*dockeracquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterDataSource("docker", func() types.DataSource { return &dockeracquisition.Source{} })
}
