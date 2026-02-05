//go:build !no_datasource_wineventlog

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/wineventlog" // register the datasource
