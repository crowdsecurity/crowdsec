package climetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

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

	points, err := ScrapeMetrics(ctx, url)
	if err != nil {
		return err
	}

	log.Debugf("Finished reading metrics output, %d entries", len(points))
	ms.processPrometheusMetrics(points)

	return nil
}

func (ms metricStore) processPrometheusMetrics(result []MetricPoint) {
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

	for _, p := range result {
		if !strings.HasPrefix(p.Name, "cs_") {
			continue
		}

		name, ok := p.Labels["name"]
		if !ok {
			log.Debugf("no name in Metric %v", p.Labels)
	}

	source, ok := p.Labels["source"]
	if !ok {
		log.Debugf("no source in Metric %v for %s", p.Labels, p.Name)
	} else {
		if srctype, ok := p.Labels["type"]; ok {
			source = srctype + ":" + source
		}
	}

	machine := p.Labels["machine"]
	bouncer := p.Labels["bouncer"]

	route := p.Labels["route"]
	method := p.Labels["method"]

	reason := p.Labels["reason"]
	origin := p.Labels["origin"]
	action := p.Labels["action"]

	appsecEngine := p.Labels["appsec_engine"]
	appsecRule := p.Labels["rule_name"]

	mtype := p.Labels["type"]

	ival := int(p.Value)

	switch p.Name {
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
			mLapiDecision.Process(bouncer, p.Name, ival)
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
			log.Debugf("unknown: %+v", p.Name)
			continue
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
			// always ok, but keep nilaway happy
			if sec, ok := want[section]; ok && sec != nil {
				sec.Table(out, wantColor, noUnit, showEmpty)
			}
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
