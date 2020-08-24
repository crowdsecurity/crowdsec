package main

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/jamiealquiza/tachymeter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"net/http"

	log "github.com/sirupsen/logrus"

	"runtime"
)

var (
	parseStat     *tachymeter.Tachymeter
	bucketStat    *tachymeter.Tachymeter
	outputStat    *tachymeter.Tachymeter
	linesReadOK   uint64
	linesReadKO   uint64
	linesParsedOK uint64
	linesParsedKO uint64
	linesPouredOK uint64
	linesPouredKO uint64
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

	if cConfig.Profiling {
		var memoryStats runtime.MemStats
		runtime.ReadMemStats(&memoryStats)

		log.Infof("parser evt/s : %s", parseStat.Calc())
		log.Infof("bucket pour evt/s : %s", bucketStat.Calc())
		log.Infof("outputs evt/s : %s", outputStat.Calc())
		log.Infof("Alloc = %v MiB", bToMb(memoryStats.Alloc))
		log.Infof("TotalAlloc = %v MiB", bToMb(memoryStats.TotalAlloc))
		log.Infof("Sys = %v MiB", bToMb(memoryStats.Sys))
		log.Infof("NumGC = %v", memoryStats.NumGC)
		log.Infof("Lines read ok : %d", linesReadOK)
		if linesReadKO > 0 {
			log.Infof("Lines discarded : %d (%.2f%%)", linesReadKO, float64(linesReadKO)/float64(linesReadOK)*100.0)
		}
		log.Infof("Lines parsed ok : %d", linesParsedOK)
		if linesParsedKO > 0 {
			log.Infof("Lines unparsed : %d (%.2f%%)", linesParsedKO, float64(linesParsedKO)/float64(linesParsedOK)*100.0)
		}
		log.Infof("Lines poured ok : %d", linesPouredOK)
		if linesPouredKO > 0 {
			log.Infof("Lines never poured : %d (%.2f%%)", linesPouredKO, float64(linesPouredKO)/float64(linesPouredOK)*100.0)
		}
		log.Infof("Writting metrics dump to %s", cConfig.WorkingFolder+"/crowdsec.profile")
		if err := prometheus.WriteToTextfile(cConfig.WorkingFolder+"/crowdsec.profile", prometheus.DefaultGatherer); err != nil {
			log.Errorf("failed to write metrics to %s : %s", cConfig.WorkingFolder+"/crowdsec.profile", err)
		}
	}
}

func runTachymeter(HTTPListen string) {
	log.Warningf("Starting profiling and http server")
	/*Tachymeter for global perfs */
	parseStat = tachymeter.New(&tachymeter.Config{Size: 100})
	bucketStat = tachymeter.New(&tachymeter.Config{Size: 100})
	outputStat = tachymeter.New(&tachymeter.Config{Size: 100})
	log.Fatal(http.ListenAndServe(HTTPListen, nil))
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
