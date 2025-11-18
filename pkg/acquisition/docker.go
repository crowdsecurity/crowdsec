//go:build !no_datasource_docker

package acquisition

import (
	dockeracquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker"
)

var (
	// verify interface compliance
	_ DataSource      = (*dockeracquisition.Source)(nil)
	_ DSNConfigurer   = (*dockeracquisition.Source)(nil)
	_ Fetcher         = (*dockeracquisition.Source)(nil)
	_ Tailer          = (*dockeracquisition.Source)(nil)
	_ MetricsProvider = (*dockeracquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("docker", func() DataSource { return &dockeracquisition.Source{} })
}
