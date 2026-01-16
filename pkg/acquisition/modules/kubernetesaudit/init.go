package kubernetesauditacquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*Source)(nil)
	_ types.Tailer          = (*Source)(nil)
	_ types.MetricsProvider = (*Source)(nil)
)

const ModuleName = "k8s-audit"

//nolint:gochecknoinits
func init() {
	registry.RegisterFactory(ModuleName, func() types.DataSource { return &Source{} })
}
