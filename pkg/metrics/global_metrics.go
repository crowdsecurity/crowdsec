package metrics

import (
	"github.com/crowdsecurity/go-cs-lib/version"
	"github.com/prometheus/client_golang/prometheus"
)

var GlobalParserHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_total",
		Help: "Total events entered the parser.",
	},
	[]string{"source", "type"},
)

var GlobalParserHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ok_total",
		Help: "Total events were successfully parsed.",
	},
	[]string{"source", "type"},
)

var GlobalParserHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ko_total",
		Help: "Total events were unsuccessfully parsed.",
	},
	[]string{"source", "type"},
)

var GlobalBucketPourKo = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_bucket_pour_ko_total",
		Help: "Total events were not poured in a bucket.",
	},
)

var GlobalBucketPourOk = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_bucket_pour_ok_total",
		Help: "Total events were poured in at least one bucket.",
	},
)

var GlobalCsInfo = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name:        "cs_info",
		Help:        "Information about Crowdsec.",
		ConstLabels: prometheus.Labels{"version": version.String()},
	},
)

var GlobalActiveDecisions = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_active_decisions",
		Help: "Number of active decisions.",
	},
	[]string{"reason", "origin", "action"},
)

var GlobalAlerts = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_alerts",
		Help: "Number of alerts (excluding CAPI).",
	},
	[]string{"reason"},
)

var GlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent parsing a line",
		Name:    "cs_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"type", "source"},
)

var GlobalPourHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cs_bucket_pour_seconds",
		Help:    "Time spent pouring an event to buckets.",
		Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.015, 0.02, 0.03, 0.04, 0.05},
	},
	[]string{"type", "source"},
)
