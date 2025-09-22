//go:build !no_datasource_k8saudit

package acquisition

import (
	k8sauditacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetesaudit"
)

var (
	// verify interface compliance
	_ DataSource      = (*k8sauditacquisition.KubernetesAuditSource)(nil)
	_ Tailer          = (*k8sauditacquisition.KubernetesAuditSource)(nil)
	_ MetricsProvider = (*k8sauditacquisition.KubernetesAuditSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("k8s-audit", func() DataSource { return &k8sauditacquisition.KubernetesAuditSource{} })
}
