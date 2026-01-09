//go:build !no_datasource_syslog

package acquisition

import (
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource          = (*syslogacquisition.Source)(nil)
	_ types.RestartableStreamer = (*syslogacquisition.Source)(nil)
	_ types.MetricsProvider     = (*syslogacquisition.Source)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("syslog", func() types.DataSource { return &syslogacquisition.Source{} })
}
