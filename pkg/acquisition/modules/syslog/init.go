package syslogacquisition

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/registry"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
)

var (
	// verify interface compliance
	_ types.DataSource          = (*Source)(nil)
	_ types.RestartableStreamer = (*Source)(nil)
	_ types.MetricsProvider     = (*Source)(nil)
)

const ModuleName = "syslog"

//nolint:gochecknoinits
func init() {
	registry.RegisterFactory(ModuleName, func() types.DataSource { return &Source{} })
}
