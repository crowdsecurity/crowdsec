//go:build !no_datasource_syslog

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog" // register the datasource
