package metrics

import (
	"github.com/crowdsecurity/go-cs-lib/version"
	"github.com/prometheus/client_golang/prometheus"
)

const GlobalParserHitsMetricName = "cs_parser_hits_total"

var GlobalParserHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: GlobalParserHitsMetricName,
		Help: "Total events entered the parser.",
	},
	[]string{"source", "type"},
)

const GlobalParserHitsOkMetricName = "cs_parser_hits_ok_total"

var GlobalParserHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: GlobalParserHitsOkMetricName,
		Help: "Total events were successfully parsed.",
	},
	[]string{"source", "type", "acquis_type"},
)

const GlobalParserHitsKoMetricName = "cs_parser_hits_ko_total"

var GlobalParserHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: GlobalParserHitsKoMetricName,
		Help: "Total events were unsuccessfully parsed.",
	},
	[]string{"source", "type", "acquis_type"},
)

const GlobalBucketPourKoMetricName = "cs_bucket_pour_ko_total"

var GlobalBucketPourKo = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: GlobalBucketPourKoMetricName,
		Help: "Total events were not poured in a bucket.",
	},
)

const GlobalBucketPourOkMetricName = "cs_bucket_pour_ok_total"

var GlobalBucketPourOk = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: GlobalBucketPourOkMetricName,
		Help: "Total events were poured in at least one bucket.",
	},
)

const GlobalCsInfoMetricName = "cs_info"

var GlobalCsInfo = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name:        GlobalCsInfoMetricName,
		Help:        "Information about Crowdsec.",
		ConstLabels: prometheus.Labels{"version": version.String()},
	},
)

const GlobalActiveDecisionsMetricName = "cs_active_decisions"

var GlobalActiveDecisions = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: GlobalActiveDecisionsMetricName,
		Help: "Number of active decisions.",
	},
	[]string{"reason", "origin", "action"},
)

const GlobalAlertsMetricName = "cs_alerts"

var GlobalAlerts = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: GlobalAlertsMetricName,
		Help: "Number of alerts (excluding CAPI).",
	},
	[]string{"reason"},
)

const GlobalParsingHistogramMetricName = "cs_parsing_time_seconds"

var GlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent parsing a line",
		Name:    GlobalParsingHistogramMetricName,
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"type", "source"},
)

const GlobalPourHistogramMetricName = "cs_bucket_pour_seconds"

var GlobalPourHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    GlobalPourHistogramMetricName,
		Help:    "Time spent pouring an event to buckets.",
		Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.015, 0.02, 0.03, 0.04, 0.05},
	},
	[]string{"type", "source"},
)
