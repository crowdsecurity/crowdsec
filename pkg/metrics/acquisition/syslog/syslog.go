//go:build !no_datasource_syslog

package syslog_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const SyslogDataSourceLinesReceivedMetricName = "cs_syslogsource_hits_total"

var SyslogDataSourceLinesReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: SyslogDataSourceLinesReceivedMetricName,
		Help: "Total lines that were received.",
	},
	[]string{"source", "datasource_type", "label_type"})

const SyslogDataSourceLinesParsedMetricName = "cs_syslogsource_parsed_total"

var SyslogDataSourceLinesParsed = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: SyslogDataSourceLinesParsedMetricName,
		Help: "Total lines that were successfully parsed",
	},
	[]string{"source", "type", "datasource_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(SyslogDataSourceLinesParsedMetricName)
}
