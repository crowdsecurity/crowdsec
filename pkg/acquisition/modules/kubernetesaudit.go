//go:build !no_datasource_k8saudit

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetesaudit" // register the datasource
