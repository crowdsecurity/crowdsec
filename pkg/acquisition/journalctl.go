// +build !no_datasource_journalctl

package acquisition

import (
	journalctlacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/journalctl"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["journalctl"] = func() DataSource { return &journalctlacquisition.JournalCtlSource{} }
}
