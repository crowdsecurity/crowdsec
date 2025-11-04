package journalctlacquisition

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func (*JournalCtlSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.JournalCtlDataSourceLinesRead}
}

func (*JournalCtlSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.JournalCtlDataSourceLinesRead}
}
