// +build !no_datasource_k8saudit

package acquisition

import (
	k8sauditacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetesaudit"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["k8s-audit"] = func() DataSource { return &k8sauditacquisition.KubernetesAuditSource{} }
}
