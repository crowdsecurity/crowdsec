//go:build  !no_datasource_appsec

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/appsec" // register the datasource
