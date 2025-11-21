//go:build !no_datasource_k8s_podlogs

package acquisition

import (
	kubernetespodlogs "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetespodlogs"
)

var (
	// verify interface compliance
	_ DataSource      = (*kubernetespodlogs.KubernetesPodLogsSource)(nil)
	_ Tailer          = (*kubernetespodlogs.KubernetesPodLogsSource)(nil)
	_ MetricsProvider = (*kubernetespodlogs.KubernetesPodLogsSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("k8s-podlogs", func() DataSource { return &kubernetespodlogs.KubernetesPodLogsSource{} })
}
