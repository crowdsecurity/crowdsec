package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const AppsecGlobalParsingHistogramMetricName = "cs_appsec_parsing_time_seconds"

var AppsecGlobalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the Application Security Engine.",
		Name:    AppsecGlobalParsingHistogramMetricName,
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

const AppsecInbandParsingHistogramMetricName = "cs_appsec_inband_parsing_time_seconds"

var AppsecInbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the inband Application Security Engine.",
		Name:    AppsecInbandParsingHistogramMetricName,
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

const AppsecOutbandParsingHistogramMetricName = "cs_appsec_outband_parsing_time_seconds"

var AppsecOutbandParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent processing a request by the Application Security Engine.",
		Name:    AppsecOutbandParsingHistogramMetricName,
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.0050, 0.01, 0.025, 0.05, 0.1, 0.25},
	},
	[]string{"source", "appsec_engine"},
)

const AppsecReqCounterMetricName = "cs_appsec_reqs_total"

var AppsecReqCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecReqCounterMetricName,
		Help: "Total events processed by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

const AppsecBlockCounterMetricName = "cs_appsec_block_total"

var AppsecBlockCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecBlockCounterMetricName,
		Help: "Total events blocked by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

const AppsecRuleHitsMetricName = "cs_appsec_rule_hits"

var AppsecRuleHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecRuleHitsMetricName,
		Help: "Count of triggered rule, by rule_name, type (inband/outofband), appsec_engine and source",
	},
	[]string{"rule_name", "type", "appsec_engine", "source"},
)

const AppsecFingerprintMismatchMetricName = "cs_appsec_fingerprint_mismatch_total"

var AppsecFingerprintMismatch = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecFingerprintMismatchMetricName,
		Help: "Count of fingerprint mismatch signals fired per reason and severity.",
	},
	[]string{"reason", "severity", "appsec_engine"},
)

// Bot detection / WAF challenge lifecycle counters. The funnel is
// requested → submitted → accepted | rejected, with a `kind` label
// distinguishing sub-outcomes (e.g. accepted{kind="granted"} for operator
// allowlist grants, rejected{kind="cookie"} for tampered/expired cookies
// caught on subsequent requests).

const AppsecChallengeRequestedMetricName = "cs_appsec_challenge_requested_total"

var AppsecChallengeRequested = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecChallengeRequestedMetricName,
		Help: "Total challenges served by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

const AppsecChallengeSubmittedMetricName = "cs_appsec_challenge_submitted_total"

var AppsecChallengeSubmitted = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecChallengeSubmittedMetricName,
		Help: "Total challenge responses received by the Application Security Engine.",
	},
	[]string{"source", "appsec_engine"},
)

const AppsecChallengeAcceptedMetricName = "cs_appsec_challenge_accepted_total"

// AppsecChallengeAccepted carries an extra `reason` label so operator-driven
// grants (kind="granted") can be split by the GrantChallengeCookie reason.
// For kind="solved" the label is empty: regular submissions have no
// per-issue reason.
var AppsecChallengeAccepted = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecChallengeAcceptedMetricName,
		Help: "Total challenge cookies issued, by kind (solved=valid submission, granted=GrantChallengeCookie) and (for granted) operator-supplied reason.",
	},
	[]string{"source", "appsec_engine", "kind", "reason"},
)

const AppsecChallengeRejectedMetricName = "cs_appsec_challenge_rejected_total"

var AppsecChallengeRejected = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecChallengeRejectedMetricName,
		Help: "Total challenge/cookie rejections, by kind (protocol=crypto/PoW failure, submission=RejectSubmission, cookie=invalid incoming cookie) and reason.",
	},
	[]string{"source", "appsec_engine", "kind", "reason"},
)

const AppsecValidationOKCounterMetricName = "cs_appsec_validation_ok_total"

// AppsecValidationOKCounter counts successful OpenAPI schema validations.
var AppsecValidationOKCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecValidationOKCounterMetricName,
		Help: "Count of requests that passed OpenAPI schema validation, by schema_ref.",
	},
	[]string{"source", "appsec_engine", "schema_ref"},
)

const AppsecValidationFailedCounterMetricName = "cs_appsec_validation_failed_total"

// AppsecValidationFailedCounter counts failed OpenAPI schema validations.
// reason is one of a fixed set — "parameter", "request_body", "security",
// "route_not_found", "method_not_allowed", "internal".
var AppsecValidationFailedCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecValidationFailedCounterMetricName,
		Help: "Count of requests that failed OpenAPI schema validation, by schema_ref and reason.",
	},
	[]string{"source", "appsec_engine", "schema_ref", "reason"},
)

// Bot detection / WAF challenge infrastructure counters. These track the
// internal upkeep of the challenge runtime rather than visitor behavior.

const AppsecChallengeKepochGeneratedMetricName = "cs_appsec_challenge_kepoch_generated_total"

var AppsecChallengeKepochGenerated = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: AppsecChallengeKepochGeneratedMetricName,
		Help: "Total per-epoch challenge signing keys derived (k_epoch regenerations).",
	},
)

const AppsecChallengeKepochEvictedMetricName = "cs_appsec_challenge_kepoch_evicted_total"

var AppsecChallengeKepochEvicted = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: AppsecChallengeKepochEvictedMetricName,
		Help: "Total per-epoch challenge signing keys evicted from the keyring cache (generated minus evicted is the live cache size).",
	},
)

const AppsecChallengeReobfuscationMetricName = "cs_appsec_challenge_reobfuscation_total"

// Each obfuscation pass is CPU-expensive, so this is the headline signal for
// obfuscator load. Only the per-epoch sign-key module is re-obfuscated at
// runtime now (bundle="dynamic"); the public challenge code is obfuscated once
// at build time and the fpscanner is served unobfuscated, so the historical
// bundle="library" series is retired.
var AppsecChallengeReobfuscation = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: AppsecChallengeReobfuscationMetricName,
		Help: "Total JS obfuscation passes run by the challenge runtime, by bundle (dynamic=per-epoch sign-key module).",
	},
	[]string{"bundle"},
)

const AppsecChallengeDynamicModuleEvictedMetricName = "cs_appsec_challenge_dynamic_module_evicted_total"

var AppsecChallengeDynamicModuleEvicted = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: AppsecChallengeDynamicModuleEvictedMetricName,
		Help: "Total per-epoch dynamic-module cache entries evicted once their epoch left the keyring live window.",
	},
)
