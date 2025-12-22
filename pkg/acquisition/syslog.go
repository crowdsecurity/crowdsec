//go:build !no_datasource_syslog

package acquisition

import (
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
)

var (
	// verify interface compliance
	_ DataSource          = (*syslogacquisition.Source)(nil)
	_ RestartableStreamer = (*syslogacquisition.Source)(nil)
	_ MetricsProvider     = (*syslogacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("syslog", func() DataSource { return &syslogacquisition.Source{} })
}
