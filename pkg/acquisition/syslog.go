//go:build !no_datasource_syslog

package acquisition

import (
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("syslog", func() DataSource { return &syslogacquisition.SyslogSource{} })
}
