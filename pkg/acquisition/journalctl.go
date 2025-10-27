//go:build !no_datasource_journalctl

package acquisition

import (
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
)

var (
	// verify interface compliance
	_ DataSource      = (*journalctlacquisition.JournalCtlSource)(nil)
	_ DSNConfigurer   = (*journalctlacquisition.JournalCtlSource)(nil)
	_ Fetcher         = (*journalctlacquisition.JournalCtlSource)(nil)
	_ Tailer          = (*journalctlacquisition.JournalCtlSource)(nil)
	_ MetricsProvider = (*journalctlacquisition.JournalCtlSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("journalctl", func() DataSource { return &journalctlacquisition.JournalCtlSource{} })
}
