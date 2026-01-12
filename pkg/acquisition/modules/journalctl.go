//go:build !no_datasource_journalctl

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl" // register the datasource
