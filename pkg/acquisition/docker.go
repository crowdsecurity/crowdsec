//go:build !no_datasource_docker

package acquisition

import (
	dockeracquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("docker", func() DataSource { return &dockeracquisition.DockerSource{} })
}
