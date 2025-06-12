package syslog_metrics

import "github.com/prometheus/client_golang/prometheus"

const SyslogDataSourceLinesReceivedMetricName = "cs_syslogsource_hits_total"

var SyslogDataSourceLinesReceived = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: SyslogDataSourceLinesReceivedMetricName,
		Help: "Total lines that were received.",
	},
	[]string{"source"})

const SyslogDataSourceLinesParsedMetricName = "cs_syslogsource_parsed_total"

var SyslogDataSourceLinesParsed = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: SyslogDataSourceLinesParsedMetricName,
		Help: "Total lines that were successfully parsed",
	},
	[]string{"source", "type"})
