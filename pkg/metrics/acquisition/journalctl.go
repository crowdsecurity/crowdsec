//go:build !no_datasource_journalctl

package acquisition

import (
	"github.com/prometheus/client_golang/prometheus"
)

const JournalCtlDataSourceLinesReadMetricName = "cs_journalctlsource_hits_total"

var JournalCtlDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: JournalCtlDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "label_type"})

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(JournalCtlDataSourceLinesReadMetricName)
}
