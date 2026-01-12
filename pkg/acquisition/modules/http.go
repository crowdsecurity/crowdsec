//go:build !no_datasource_http

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/http" // register the datasource
