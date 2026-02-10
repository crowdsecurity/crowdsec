//go:build !no_datasource_kubernetespodlogs

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kubernetes" // register the datasource
