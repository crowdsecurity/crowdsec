// +build !no_datasource_syslog

package acquisition

import (
	syslogacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["syslog"] = func() DataSource { return &syslogacquisition.SyslogSource{} }
}
