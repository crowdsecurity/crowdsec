//go:build !no_datasource_journalctl

package journalctl_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const JournalCtlDataSourceLinesReadMetricName = "cs_journalctlsource_hits_total"

var JournalCtlDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: JournalCtlDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(JournalCtlDataSourceLinesReadMetricName)
}
