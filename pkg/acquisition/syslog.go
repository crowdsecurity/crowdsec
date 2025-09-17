//go:build !no_datasource_syslog

package acquisition

import (
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
)

var (
	// verify interface compliance
	_ DataSource      = (*syslogacquisition.SyslogSource)(nil)
	_ Tailer          = (*syslogacquisition.SyslogSource)(nil)
	_ MetricsProvider = (*syslogacquisition.SyslogSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("syslog", func() DataSource { return &syslogacquisition.SyslogSource{} })
}
