package main

import (
	"fmt"

	v1 "github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"net/http"

	log "github.com/sirupsen/logrus"
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
		ConstLabels: prometheus.Labels{"version": cwversion.VersionStr()},
	},
)

var globalActiveDecisions = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_active_decisions",
		Help: "Number of active decisions.",
	},
	[]string{"scenario", "origin", "action"},
)

var globalAlerts = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_alerts",
		Help: "Number of alerts (excluding CAPI).",
	},
	[]string{"scenario"},
)

func computeDynamicMetrics(next http.Handler, dbClient *database.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dbClient == nil {
			next.ServeHTTP(w, r)
			return
		}

		decisionsFilters := make(map[string][]string, 0)
		decisions, err := dbClient.QueryAllDecisionsWithFilters(decisionsFilters)
		if err != nil {
			log.Errorf("Error querying decisions for metrics: %v", err)
			next.ServeHTTP(w, r)
			return
		}
		globalActiveDecisions.Reset()
		for _, d := range decisions {
			globalActiveDecisions.With(prometheus.Labels{"scenario": d.Scenario, "origin": d.Origin, "action": d.Type}).Inc()
		}

		alertsFilter := map[string][]string{
			"include_capi": {"false"},
		}

		globalAlerts.Reset()

		alerts, err := dbClient.QueryAlertWithFilter(alertsFilter)

		if err != nil {
			log.Errorf("Error querying alerts for metrics: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		for _, a := range alerts {
			globalAlerts.With(prometheus.Labels{"scenario": a.Scenario}).Inc()
		}

		next.ServeHTTP(w, r)
	})
}

func registerPrometheus(config *csconfig.PrometheusCfg, dbConfig *csconfig.DatabaseCfg) {
	if !config.Enabled {
		return
	}
	if config.ListenAddr == "" {
		log.Warningf("prometheus is enabled, but the listen address is empty, using '127.0.0.1'")
		config.ListenAddr = "127.0.0.1"
	}
	if config.ListenPort == 0 {
		log.Warningf("prometheus is enabled, but the listen port is empty, using '6060'")
		config.ListenPort = 6060
	}

	var dbClient *database.Client
	var err error

	if dbConfig != nil {
		dbClient, err = database.NewClient(dbConfig)

		if err != nil {
			log.Errorf("unable to create database client: %v", err)
			return
		}
	}

	defer types.CatchPanic("crowdsec/registerPrometheus")
	/*Registering prometheus*/
	/*If in aggregated mode, do not register events associated to a source, keeps cardinality low*/
	if config.Level == "aggregated" {
		log.Infof("Loading aggregated prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			globalCsInfo,
			leaky.BucketsUnderflow, leaky.BucketsCanceled, leaky.BucketsInstanciation, leaky.BucketsOverflow,
			v1.LapiRouteHits,
			leaky.BucketsCurrentCount)
	} else {
		log.Infof("Loading prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			parser.NodesHits, parser.NodesHitsOk, parser.NodesHitsKo,
			globalCsInfo,
			v1.LapiRouteHits, v1.LapiMachineHits, v1.LapiBouncerHits, v1.LapiNilDecisions, v1.LapiNonNilDecisions, v1.LapiResponseTime,
			leaky.BucketsPour, leaky.BucketsUnderflow, leaky.BucketsCanceled, leaky.BucketsInstanciation, leaky.BucketsOverflow, leaky.BucketsCurrentCount,
			globalActiveDecisions, globalAlerts)

	}
	http.Handle("/metrics", computeDynamicMetrics(promhttp.Handler(), dbClient))
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort), nil); err != nil {
		log.Warningf("prometheus: %s", err)
	}
}
