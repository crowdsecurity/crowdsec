package journalctl_metrics

import "github.com/prometheus/client_golang/prometheus"

const JournalCtlDataSourceLinesReadMetricName = "cs_journalctlsource_hits_total"

var JournalCtlDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: JournalCtlDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source"})
