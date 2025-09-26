//go:build !no_datasource_docker

package acquisition

import (
	dockeracquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker"
)

var (
	// verify interface compliance
	_ DataSource      = (*dockeracquisition.DockerSource)(nil)
	_ DSNConfigurer   = (*dockeracquisition.DockerSource)(nil)
	_ Fetcher         = (*dockeracquisition.DockerSource)(nil)
	_ Tailer          = (*dockeracquisition.DockerSource)(nil)
	_ MetricsProvider = (*dockeracquisition.DockerSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("docker", func() DataSource { return &dockeracquisition.DockerSource{} })
}
