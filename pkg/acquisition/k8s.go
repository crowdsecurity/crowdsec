//go:build !no_datasource_k8saudit

package acquisition

import (
	k8sauditacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetesaudit"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource      = (*k8sauditacquisition.Source)(nil)
	_ types.Tailer          = (*k8sauditacquisition.Source)(nil)
	_ types.MetricsProvider = (*k8sauditacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registry.RegisterDataSource("k8s-audit", func() types.DataSource { return &k8sauditacquisition.Source{} })
}
