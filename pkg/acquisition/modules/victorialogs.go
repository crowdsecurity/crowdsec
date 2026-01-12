//go:build !no_datasource_victorialogs

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/victorialogs" // register the datasource
