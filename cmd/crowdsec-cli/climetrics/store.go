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
		"acquisition":            statAcquis{},
		"alerts":                 statAlert{},
		"bouncers":               &statBouncer{},
		"appsec-engine":          statAppsecEngine{},
		"appsec-rule":            statAppsecRule{},
		"appsec-challenge":       newStatAppsecChallenge(),
		"appsec-challenge-infra": statAppsecChallengeInfra{},
		"decisions":              statDecision{},
		"lapi":                   statLapi{},
		"lapi-bouncer":           statLapiBouncer{},
		"lapi-decisions":         statLapiDecision{},
		"lapi-machine":           statLapiMachine{},
		"parsers":                statParser{},
		"scenarios":              statBucket{},
		"stash":                  statStash{},
		"whitelists":             statWhitelist{},
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

// metricLabels holds the label values extracted from a single Prometheus point.
type metricLabels struct {
	name         string
	source       string
	machine      string
	bouncer      string
	route        string
	method       string
	reason       string
	origin       string
	action       string
	appsecEngine string
	appsecRule   string
	// kind is carried by the appsec-challenge accepted/rejected counters
	// to distinguish sub-outcomes; empty for every other metric.
	kind string
	// bundle is carried by the challenge re-obfuscation counter
	// (dynamic vs library); empty for every other metric.
	bundle string
	mtype  string
}

func extractLabels(p MetricPoint) metricLabels {
	name, ok := p.Labels["name"]
	if !ok {
		log.Debugf("no name in Metric %v", p.Labels)
	}

	source, ok := p.Labels["source"]
	if !ok {
		log.Debugf("no source in Metric %v for %s", p.Labels, p.Name)
	} else if srctype, ok := p.Labels["type"]; ok {
		source = srctype + ":" + source
	}

	return metricLabels{
		name:         name,
		source:       source,
		machine:      p.Labels["machine"],
		bouncer:      p.Labels["bouncer"],
		route:        p.Labels["route"],
		method:       p.Labels["method"],
		reason:       p.Labels["reason"],
		origin:       p.Labels["origin"],
		action:       p.Labels["action"],
		appsecEngine: p.Labels["appsec_engine"],
		appsecRule:   p.Labels["rule_name"],
		kind:         p.Labels["kind"],
		bundle:       p.Labels["bundle"],
		mtype:        p.Labels["type"],
	}
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

		l := extractLabels(p)

		ival := int(p.Value)

		switch p.Name {
		//
		// buckets
		//
		case metrics.BucketsInstantiationMetricName:
			mBucket.Process(l.name, "instantiation", ival)
		case metrics.BucketsCurrentCountMetricName:
			mBucket.Process(l.name, "curr_count", ival)
		case metrics.BucketsOverflowMetricName:
			mBucket.Process(l.name, "overflow", ival)
		case metrics.BucketPouredMetricName:
			mBucket.Process(l.name, "pour", ival)
			mAcquis.Process(l.source, "pour", ival)
		case metrics.BucketsUnderflowMetricName:
			mBucket.Process(l.name, "underflow", ival)
		//
		// parsers
		//
		case metrics.GlobalParserHitsMetricName:
			mAcquis.Process(l.source, "reads", ival)
		case metrics.GlobalParserHitsOkMetricName:
			mAcquis.Process(l.source, "parsed", ival)
		case metrics.GlobalParserHitsKoMetricName:
			mAcquis.Process(l.source, "unparsed", ival)
		case metrics.NodesHitsMetricName:
			mParser.Process(l.name, "hits", ival)
		case metrics.NodesHitsOkMetricName:
			mParser.Process(l.name, "parsed", ival)
		case metrics.NodesHitsKoMetricName:
			mParser.Process(l.name, "unparsed", ival)
		//
		// whitelists
		//
		case metrics.NodesWlHitsMetricName:
			mWhitelist.Process(l.name, l.reason, "hits", ival)
		case metrics.NodesWlHitsOkMetricName:
			mWhitelist.Process(l.name, l.reason, "whitelisted", ival)
			// track as well whitelisted lines at acquis level
			mAcquis.Process(l.source, "whitelisted", ival)
		//
		// lapi
		//
		case metrics.LapiRouteHitsMetricName:
			mLapi.Process(l.route, l.method, ival)
		case metrics.LapiMachineHitsMetricName:
			mLapiMachine.Process(l.machine, l.route, l.method, ival)
		case metrics.LapiBouncerHitsMetricName:
			mLapiBouncer.Process(l.bouncer, l.route, l.method, ival)
		case metrics.LapiNilDecisionsMetricName, metrics.LapiNonNilDecisionsMetricName:
			mLapiDecision.Process(l.bouncer, p.Name, ival)
		//
		// decisions
		//
		case metrics.GlobalActiveDecisionsMetricName:
			mDecision.Process(l.reason, l.origin, l.action, ival)
		case metrics.GlobalAlertsMetricName:
			mAlert.Process(l.reason, ival)
		//
		// stash
		//
		case metrics.CacheMetricName:
			mStash.Process(l.name, l.mtype, ival)
		//
		// appsec
		//
		case "cs_appsec_reqs_total":
			mAppsecEngine.Process(l.appsecEngine, "processed", ival)
		case "cs_appsec_block_total":
			mAppsecEngine.Process(l.appsecEngine, "blocked", ival)
		case "cs_appsec_rule_hits":
			mAppsecRule.Process(l.appsecEngine, l.appsecRule, "triggered", ival)
		default:
			// bot detection / challenge metrics live in their own handler to
			// keep this switch's complexity in check.
			if ms.processAppsecChallengeMetric(p.Name, l, ival) {
				continue
			}

			log.Debugf("unknown: %+v", p.Name)
			continue
		}
	}
}

// processAppsecChallengeMetric handles the bot-detection / challenge lifecycle
// and infrastructure metrics. It lives apart from processPrometheusMetrics
// because its nested kind/bundle switches would otherwise push that function
// over the cyclomatic-complexity limit. Returns false for unrecognized metrics.
func (ms metricStore) processAppsecChallengeMetric(name string, l metricLabels, ival int) bool {
	mAppsecEngine := ms["appsec-engine"].(statAppsecEngine)
	mAppsecChallenge := ms["appsec-challenge"].(*statAppsecChallenge)
	mAppsecChallengeInfra := ms["appsec-challenge-infra"].(statAppsecChallengeInfra)

	switch name {
	//
	// bot detection / challenge lifecycle
	//
	case metrics.AppsecChallengeRequestedMetricName:
		mAppsecEngine.Process(l.appsecEngine, "challenge_requested", ival)
		mAppsecChallenge.Process(l.appsecEngine, "requested", ival)
	case metrics.AppsecChallengeSubmittedMetricName:
		mAppsecChallenge.Process(l.appsecEngine, "submitted", ival)
	case metrics.AppsecChallengeAcceptedMetricName:
		mAppsecEngine.Process(l.appsecEngine, "challenge_accepted", ival)
		switch l.kind {
		case "solved":
			mAppsecChallenge.Process(l.appsecEngine, "solved", ival)
		case "granted":
			mAppsecChallenge.Process(l.appsecEngine, "granted", ival)
			mAppsecChallenge.ProcessReason(l.appsecEngine, "granted", l.reason, ival)
		}
	case metrics.AppsecChallengeRejectedMetricName:
		mAppsecEngine.Process(l.appsecEngine, "challenge_rejected", ival)
		switch l.kind {
		case "protocol":
			mAppsecChallenge.Process(l.appsecEngine, "rejected_protocol", ival)
			mAppsecChallenge.ProcessReason(l.appsecEngine, "protocol", l.reason, ival)
		case "submission":
			mAppsecChallenge.Process(l.appsecEngine, "rejected_submission", ival)
			mAppsecChallenge.ProcessReason(l.appsecEngine, "submission", l.reason, ival)
		case "cookie":
			mAppsecChallenge.Process(l.appsecEngine, "rejected_cookie", ival)
			mAppsecChallenge.ProcessReason(l.appsecEngine, "cookie", l.reason, ival)
		}
	//
	// bot detection / challenge infrastructure (process-global, no engine label)
	//
	case metrics.AppsecChallengeKepochGeneratedMetricName:
		mAppsecChallengeInfra.Process("kepoch_generated", ival)
	case metrics.AppsecChallengeKepochEvictedMetricName:
		mAppsecChallengeInfra.Process("kepoch_evicted", ival)
	case metrics.AppsecChallengeReobfuscationMetricName:
		switch l.bundle {
		case "dynamic":
			mAppsecChallengeInfra.Process("reobfuscation_dynamic", ival)
		case "library":
			mAppsecChallengeInfra.Process("reobfuscation_library", ival)
		}
	case metrics.AppsecChallengeDynamicModuleEvictedMetricName:
		mAppsecChallengeInfra.Process("dynamic_module_evicted", ival)
	default:
		return false
	}

	return true
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
