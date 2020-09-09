package main

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
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
	[]string{"source"},
)
var globalParserHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ok_total",
		Help: "Total events were successfully parsed.",
	},
	[]string{"source"},
)
var globalParserHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_parser_hits_ko_total",
		Help: "Total events were unsuccessfully parsed.",
	},
	[]string{"source"},
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

func dumpMetrics() {
	var tmpFile string
	var err error

	if cConfig.DumpBuckets {
		log.Infof("!! Dumping buckets state")
		if tmpFile, err = leaky.DumpBucketsStateAt(time.Now(), buckets); err != nil {
			log.Fatalf("Failed dumping bucket state : %s", err)
		}
		log.Infof("Buckets state dumped to %s", tmpFile)
	}
}

func registerPrometheus(mode string) {
	/*Registering prometheus*/
	/*If in aggregated mode, do not register events associated to a source, keeps cardinality low*/
	if mode == "aggregated" {
		log.Infof("Loading aggregated prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			acquisition.ReaderHits, globalCsInfo,
			leaky.BucketsUnderflow, leaky.BucketsInstanciation, leaky.BucketsOverflow,
			leaky.BucketsCurrentCount)
	} else {
		log.Infof("Loading prometheus collectors")
		prometheus.MustRegister(globalParserHits, globalParserHitsOk, globalParserHitsKo,
			parser.NodesHits, parser.NodesHitsOk, parser.NodesHitsKo,
			acquisition.ReaderHits, globalCsInfo,
			leaky.BucketsPour, leaky.BucketsUnderflow, leaky.BucketsInstanciation, leaky.BucketsOverflow, leaky.BucketsCurrentCount)

	}
	http.Handle("/metrics", promhttp.Handler())
}
