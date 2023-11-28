package wafacquisition

import "github.com/prometheus/client_golang/prometheus"

var WafGlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the WAF.",
		Name:    "cs_waf_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafInbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the inband WAF.",
		Name:    "cs_waf_inband_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafOutbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the WAF.",
		Name:    "cs_waf_outband_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"source"},
)

var WafReqCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_reqs_total",
		Help: "Total events processed by the WAF.",
	},
	[]string{"source", "waap_engine"},
)

var WafBlockCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_block_total",
		Help: "Total events blocked by the WAF.",
	},
	[]string{"source", "waap_engine"},
)

var WafRuleHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_waf_rule_hits",
		Help: "Count of triggered rule, by rule_id and type (inband/outofband).",
	},
	[]string{"rule_id", "type", "waap_engine", "source"},
)
