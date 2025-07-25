package climetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"
	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type metricSection interface {
	Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool)
	Description() (string, string)
}

type metricStore map[string]metricSection

func NewMetricStore() metricStore {
	return metricStore{
		"acquisition":    statAcquis{},
		"alerts":         statAlert{},
		"bouncers":       &statBouncer{},
		"appsec-engine":  statAppsecEngine{},
		"appsec-rule":    statAppsecRule{},
		"decisions":      statDecision{},
		"lapi":           statLapi{},
		"lapi-bouncer":   statLapiBouncer{},
		"lapi-decisions": statLapiDecision{},
		"lapi-machine":   statLapiMachine{},
		"parsers":        statParser{},
		"scenarios":      statBucket{},
		"stash":          statStash{},
		"whitelists":     statWhitelist{},
	}
}

func (ms metricStore) Fetch(ctx context.Context, url string, db *database.Client) error {
	if err := ms["bouncers"].(*statBouncer).Fetch(ctx, db); err != nil {
		return err
	}

	return ms.fetchPrometheusMetrics(url)
}

func (ms metricStore) fetchPrometheusMetrics(url string) error {
	mfChan := make(chan *dto.MetricFamily, 1024)
	errChan := make(chan error, 1)

	// Start with the DefaultTransport for sane defaults.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Conservatively disable HTTP keep-alives as this program will only
	// ever need a single HTTP request.
	transport.DisableKeepAlives = true
	// Timeout early if the server doesn't even return the headers.
	transport.ResponseHeaderTimeout = time.Minute
	go func() {
		defer trace.CatchPanic("crowdsec/ShowPrometheus")

		err := prom2json.FetchMetricFamilies(url, mfChan, transport)
		if err != nil {
			errChan <- fmt.Errorf("while fetching metrics: %w", err)
			return
		}
		errChan <- nil
	}()

	result := []*prom2json.Family{}
	for mf := range mfChan {
		result = append(result, prom2json.NewFamily(mf))
	}

	if err := <-errChan; err != nil {
		return err
	}

	log.Debugf("Finished reading metrics output, %d entries", len(result))
	ms.processPrometheusMetrics(result)

	return nil
}

func (ms metricStore) processPrometheusMetrics(result []*prom2json.Family) {
	mAcquis := ms["acquisition"].(statAcquis)
	mAlert := ms["alerts"].(statAlert)
	mAppsecEngine := ms["appsec-engine"].(statAppsecEngine)
	mAppsecRule := ms["appsec-rule"].(statAppsecRule)
	mDecision := ms["decisions"].(statDecision)
	mLapi := ms["lapi"].(statLapi)
	mLapiBouncer := ms["lapi-bouncer"].(statLapiBouncer)
	mLapiDecision := ms["lapi-decisions"].(statLapiDecision)
	mLapiMachine := ms["lapi-machine"].(statLapiMachine)
	mParser := ms["parsers"].(statParser)
	mBucket := ms["scenarios"].(statBucket)
	mStash := ms["stash"].(statStash)
	mWhitelist := ms["whitelists"].(statWhitelist)

	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}

		log.Tracef("round %d", idx)

		for _, m := range fam.Metrics {
			metric, ok := m.(prom2json.Metric)
			if !ok {
				log.Debugf("failed to convert metric to prom2json.Metric")
				continue
			}

			name, ok := metric.Labels["name"]
			if !ok {
				log.Debugf("no name in Metric %v", metric.Labels)
			}

			source, ok := metric.Labels["source"]
			if !ok {
				log.Debugf("no source in Metric %v for %s", metric.Labels, fam.Name)
			} else {
				if srctype, ok := metric.Labels["type"]; ok {
					source = srctype + ":" + source
				}
			}

			value := m.(prom2json.Metric).Value
			machine := metric.Labels["machine"]
			bouncer := metric.Labels["bouncer"]

			route := metric.Labels["route"]
			method := metric.Labels["method"]

			reason := metric.Labels["reason"]
			origin := metric.Labels["origin"]
			action := metric.Labels["action"]

			appsecEngine := metric.Labels["appsec_engine"]
			appsecRule := metric.Labels["rule_name"]

			mtype := metric.Labels["type"]

			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
			}

			ival := int(fval)

			switch fam.Name {
			//
			// buckets
			//
			case metrics.BucketsInstantiationMetricName:
				mBucket.Process(name, "instantiation", ival)
			case metrics.BucketsCurrentCountMetricName:
				mBucket.Process(name, "curr_count", ival)
			case metrics.BucketsOverflowMetricName:
				mBucket.Process(name, "overflow", ival)
			case metrics.BucketPouredMetricName:
				mBucket.Process(name, "pour", ival)
				mAcquis.Process(source, "pour", ival)
			case metrics.BucketsUnderflowMetricName:
				mBucket.Process(name, "underflow", ival)
			//
			// parsers
			//
			case metrics.GlobalParserHitsMetricName:
				mAcquis.Process(source, "reads", ival)
			case metrics.GlobalParserHitsOkMetricName:
				mAcquis.Process(source, "parsed", ival)
			case metrics.GlobalParserHitsKoMetricName:
				mAcquis.Process(source, "unparsed", ival)
			case metrics.NodesHitsMetricName:
				mParser.Process(name, "hits", ival)
			case metrics.NodesHitsOkMetricName:
				mParser.Process(name, "parsed", ival)
			case metrics.NodesHitsKoMetricName:
				mParser.Process(name, "unparsed", ival)
			//
			// whitelists
			//
			case metrics.NodesWlHitsMetricName:
				mWhitelist.Process(name, reason, "hits", ival)
			case metrics.NodesWlHitsOkMetricName:
				mWhitelist.Process(name, reason, "whitelisted", ival)
				// track as well whitelisted lines at acquis level
				mAcquis.Process(source, "whitelisted", ival)
			//
			// lapi
			//
			case metrics.LapiRouteHitsMetricName:
				mLapi.Process(route, method, ival)
			case metrics.LapiMachineHitsMetricName:
				mLapiMachine.Process(machine, route, method, ival)
			case metrics.LapiBouncerHitsMetricName:
				mLapiBouncer.Process(bouncer, route, method, ival)
			case metrics.LapiNilDecisionsMetricName, metrics.LapiNonNilDecisionsMetricName:
				mLapiDecision.Process(bouncer, fam.Name, ival)
			//
			// decisions
			//
			case metrics.GlobalActiveDecisionsMetricName:
				mDecision.Process(reason, origin, action, ival)
			case metrics.GlobalAlertsMetricName:
				mAlert.Process(reason, ival)
			//
			// stash
			//
			case metrics.CacheMetricName:
				mStash.Process(name, mtype, ival)
			//
			// appsec
			//
			case "cs_appsec_reqs_total":
				mAppsecEngine.Process(appsecEngine, "processed", ival)
			case "cs_appsec_block_total":
				mAppsecEngine.Process(appsecEngine, "blocked", ival)
			case "cs_appsec_rule_hits":
				mAppsecRule.Process(appsecEngine, appsecRule, "triggered", ival)
			default:
				log.Debugf("unknown: %+v", fam.Name)
				continue
			}
		}
	}
}

func (ms metricStore) Format(out io.Writer, wantColor string, sections []string, outputFormat string, noUnit bool) error {
	// copy only the sections we want
	want := map[string]metricSection{}

	// if explicitly asking for sections, we want to show empty tables
	showEmpty := len(sections) > 0

	// if no sections are specified, we want all of them
	if len(sections) == 0 {
		sections = maptools.SortedKeys(ms)
	}

	for _, section := range sections {
		want[section] = ms[section]
	}

	switch outputFormat {
	case "human":
		for _, section := range maptools.SortedKeys(want) {
			want[section].Table(out, wantColor, noUnit, showEmpty)
		}
	case "json":
		x, err := json.MarshalIndent(want, "", " ")
		if err != nil {
			return fmt.Errorf("failed to serialize metrics: %w", err)
		}

		fmt.Fprint(out, string(x))
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}
