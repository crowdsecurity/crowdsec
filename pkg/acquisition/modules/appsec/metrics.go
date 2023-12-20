package appsecacquisition

import "github.com/prometheus/client_golang/prometheus"

var AppsecGlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the Application Security Engine.",
		Name:    "cs_appsec_parsing_time_seconds",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

var AppsecInbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the inband Application Security Engine.",
		Name:    "cs_appsec_inband_parsing_time_seconds",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

var AppsecOutbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the Application Security Engine.",
		Name:    "cs_appsec_outband_parsing_time_seconds",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

var AppsecReqCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_appsec_reqs_total",
		Help: "Total events processed by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

var AppsecBlockCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_appsec_block_total",
		Help: "Total events blocked by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

var AppsecRuleHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_appsec_rule_hits",
		Help: "Count of triggered rule, by rule_name, type (inband/outofband), appsec_engine and source",
	},
	[]string{"rule_name", "type", "appsec_engine", "source"},
)
