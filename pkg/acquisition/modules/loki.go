//go:build !no_datasource_loki

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/loki" // register the datasource
