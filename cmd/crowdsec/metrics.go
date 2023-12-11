package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers/v1"
	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

/*prometheus*/
var globalParserHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_total",
		Help: "Total events entered the parser.",
	},
	[]string{"source", "type"},
)
var globalParserHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ok_total",
		Help: "Total events were successfully parsed.",
	},
	[]string{"source", "type"},
)
var globalParserHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ko_total",
		Help: "Total events were unsuccessfully parsed.",
	},
	[]string{"source", "type"},
)

var globalBucketPourKo = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_bucket_pour_ko_total",
		Help: "Total events were not poured in a bucket.",
	},
)

var globalBucketPourOk = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cs_bucket_pour_ok_total",
		Help: "Total events were poured in at least one bucket.",
	},
)

var globalCsInfo = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name:        "cs_info",
		Help:        "Information about Crowdsec.",
		ConstLabels: prometheus.Labels{"version": version.String()},
	},
)

var globalActiveDecisions = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_active_decisions",
		Help: "Number of active decisions.",
	},
	[]string{"reason", "origin", "action"},
)

var globalAlerts = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_alerts",
		Help: "Number of alerts (excluding CAPI).",
	},
	[]string{"reason"},
)

var globalParsingHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Help:    "Time spent parsing a line",
		Name:    "cs_parsing_time_seconds",
		Buckets: []float64{0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.004, 0.005, 0.0075, 0.01},
	},
	[]string{"type", "source"},
)

var globalPourHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "cs_bucket_pour_seconds",
		Help:    "Time spent pouring an event to buckets.",
		Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.015, 0.02, 0.03, 0.04, 0.05},
	},
	[]string{"type", "source"},
)

func computeDynamicMetrics(next http.Handler, dbClient *database.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//update cache metrics (stash)
		cache.UpdateCacheMetrics()
		//update cache metrics (regexp)
		exprhelpers.UpdateRegexpCacheMetrics()

		//decision metrics are only relevant for LAPI
		if dbClient == nil {
			next.ServeHTTP(w, r)
			return
		}

		decisionsFilters := make(map[string][]string, 0)
		decisions, err := dbClient.QueryDecisionCountByScenario(decisionsFilters)
		if err != nil {
			log.Errorf("Error querying decisions for metrics: %v", err)
			next.ServeHTTP(w, r)
			return
		}
		globalActiveDecisions.Reset()
		for _, d := range decisions {
			globalActiveDecisions.With(prometheus.Labels{"reason": d.Scenario, "origin": d.Origin, "action": d.Type}).Set(float64(d.Count))
		}

		globalAlerts.Reset()

		alertsFilter := map[string][]string{
			"include_capi": {"false"},
		}

		alerts, err := dbClient.AlertsCountPerScenario(alertsFilter)

		if err != nil {
			log.Errorf("Error querying alerts for metrics: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		for k, v := range alerts {
			globalAlerts.With(prometheus.Labels{"reason": k}).Set(float64(v))
		}

		next.ServeHTTP(w, r)
	})
}

func registerPrometheus(config *csconfig.PrometheusCfg) {
	if !config.Enabled {
		return
	}

	// Registering prometheus
	// If in aggregated mode, do not register events associated with a source, to keep the cardinality low
	if config.Level == "aggregated" {
		log.Infof("Loading aggregated prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			globalCsInfo, globalParsingHistogram, globalPourHistogram,
			leaky.BucketsUnderflow, leaky.BucketsCanceled, leaky.BucketsInstantiation, leaky.BucketsOverflow,
			v1.LapiRouteHits,
			leaky.BucketsCurrentCount,
			cache.CacheMetrics, exprhelpers.RegexpCacheMetrics,
		)
	} else {
		log.Infof("Loading prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			parser.NodesHits, parser.NodesHitsOk, parser.NodesHitsKo,
			globalCsInfo, globalParsingHistogram, globalPourHistogram,
			v1.LapiRouteHits, v1.LapiMachineHits, v1.LapiBouncerHits, v1.LapiNilDecisions, v1.LapiNonNilDecisions, v1.LapiResponseTime,
			leaky.BucketsPour, leaky.BucketsUnderflow, leaky.BucketsCanceled, leaky.BucketsInstantiation, leaky.BucketsOverflow, leaky.BucketsCurrentCount,
			globalActiveDecisions, globalAlerts,
			cache.CacheMetrics, exprhelpers.RegexpCacheMetrics,
		)

	}
}

func servePrometheus(config *csconfig.PrometheusCfg, dbClient *database.Client, apiReady chan bool, agentReady chan bool) {
	if !config.Enabled {
		return
	}

	defer trace.CatchPanic("crowdsec/servePrometheus")

	http.Handle("/metrics", computeDynamicMetrics(promhttp.Handler(), dbClient))
	<-apiReady
	<-agentReady
	log.Debugf("serving metrics after %s ms", time.Since(crowdsecT0))
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort), nil); err != nil {
		log.Warningf("prometheus: %s", err)
	}
}
