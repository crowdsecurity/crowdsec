package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/maptools"
	"github.com/crowdsecurity/go-cs-lib/trace"
)

type (
	statAcquis       map[string]map[string]int
	statParser       map[string]map[string]int
	statBucket       map[string]map[string]int
	statWhitelist    map[string]map[string]map[string]int
	statLapi         map[string]map[string]int
	statLapiMachine  map[string]map[string]map[string]int
	statLapiBouncer  map[string]map[string]map[string]int
	statLapiDecision map[string]struct {
		NonEmpty int
		Empty    int
	}
	statDecision     map[string]map[string]map[string]int
	statAppsecEngine map[string]map[string]int
	statAppsecRule   map[string]map[string]map[string]int
	statAlert        map[string]int
	statStash        map[string]struct {
		Type  string
		Count int
	}
)

var (
	ErrMissingConfig   = errors.New("prometheus section missing, can't show metrics")
	ErrMetricsDisabled = errors.New("prometheus is not enabled, can't show metrics")
)

type metricSection interface {
	Table(out io.Writer, noUnit bool, showEmpty bool)
	Description() (string, string)
}

type metricStore map[string]metricSection

func NewMetricStore() metricStore {
	return metricStore{
		"acquisition":    statAcquis{},
		"scenarios":      statBucket{},
		"parsers":        statParser{},
		"lapi":           statLapi{},
		"lapi-machine":   statLapiMachine{},
		"lapi-bouncer":   statLapiBouncer{},
		"lapi-decisions": statLapiDecision{},
		"decisions":      statDecision{},
		"alerts":         statAlert{},
		"stash":          statStash{},
		"appsec-engine":  statAppsecEngine{},
		"appsec-rule":    statAppsecRule{},
		"whitelists":     statWhitelist{},
	}
}

func (ms metricStore) Fetch(url string) error {
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
			errChan <- fmt.Errorf("failed to fetch metrics: %w", err)
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
	/*walk*/

	mAcquis := ms["acquisition"].(statAcquis)
	mParser := ms["parsers"].(statParser)
	mBucket := ms["scenarios"].(statBucket)
	mLapi := ms["lapi"].(statLapi)
	mLapiMachine := ms["lapi-machine"].(statLapiMachine)
	mLapiBouncer := ms["lapi-bouncer"].(statLapiBouncer)
	mLapiDecision := ms["lapi-decisions"].(statLapiDecision)
	mDecision := ms["decisions"].(statDecision)
	mAppsecEngine := ms["appsec-engine"].(statAppsecEngine)
	mAppsecRule := ms["appsec-rule"].(statAppsecRule)
	mAlert := ms["alerts"].(statAlert)
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
			case "cs_bucket_created_total":
				mBucket.Process(name, "instantiation", ival)
			case "cs_buckets":
				mBucket.Process(name, "curr_count", ival)
			case "cs_bucket_overflowed_total":
				mBucket.Process(name, "overflow", ival)
			case "cs_bucket_poured_total":
				mBucket.Process(name, "pour", ival)
				mAcquis.Process(source, "pour", ival)
			case "cs_bucket_underflowed_total":
				mBucket.Process(name, "underflow", ival)
			//
			// parsers
			//
			case "cs_parser_hits_total":
				mAcquis.Process(source, "reads", ival)
			case "cs_parser_hits_ok_total":
				mAcquis.Process(source, "parsed", ival)
			case "cs_parser_hits_ko_total":
				mAcquis.Process(source, "unparsed", ival)
			case "cs_node_hits_total":
				mParser.Process(name, "hits", ival)
			case "cs_node_hits_ok_total":
				mParser.Process(name, "parsed", ival)
			case "cs_node_hits_ko_total":
				mParser.Process(name, "unparsed", ival)
			//
			// whitelists
			//
			case "cs_node_wl_hits_total":
				mWhitelist.Process(name, reason, "hits", ival)
			case "cs_node_wl_hits_ok_total":
				mWhitelist.Process(name, reason, "whitelisted", ival)
				// track as well whitelisted lines at acquis level
				mAcquis.Process(source, "whitelisted", ival)
			//
			// lapi
			//
			case "cs_lapi_route_requests_total":
				mLapi.Process(route, method, ival)
			case "cs_lapi_machine_requests_total":
				mLapiMachine.Process(machine, route, method, ival)
			case "cs_lapi_bouncer_requests_total":
				mLapiBouncer.Process(bouncer, route, method, ival)
			case "cs_lapi_decisions_ko_total", "cs_lapi_decisions_ok_total":
				mLapiDecision.Process(bouncer, fam.Name, ival)
			//
			// decisions
			//
			case "cs_active_decisions":
				mDecision.Process(reason, origin, action, ival)
			case "cs_alerts":
				mAlert.Process(reason, ival)
			//
			// stash
			//
			case "cs_cache_size":
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

	return nil
}

type cliMetrics struct {
	cfg configGetter
}

func NewCLIMetrics(cfg configGetter) *cliMetrics {
	return &cliMetrics{
		cfg: cfg,
	}
}

func (ms metricStore) Format(out io.Writer, sections []string, formatType string, noUnit bool) error {
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

	switch formatType {
	case "human":
		for _, section := range maptools.SortedKeys(want) {
			want[section].Table(out, noUnit, showEmpty)
		}
	case "json":
		x, err := json.MarshalIndent(want, "", " ")
		if err != nil {
			return fmt.Errorf("failed to marshal metrics: %w", err)
		}
		out.Write(x)
	case "raw":
		x, err := yaml.Marshal(want)
		if err != nil {
			return fmt.Errorf("failed to marshal metrics: %w", err)
		}
		out.Write(x)
	default:
		return fmt.Errorf("unknown format type %s", formatType)
	}

	return nil
}

func (cli *cliMetrics) show(sections []string, url string, noUnit bool) error {
	cfg := cli.cfg()

	if url != "" {
		cfg.Cscli.PrometheusUrl = url
	}

	if cfg.Prometheus == nil {
		return ErrMissingConfig
	}

	if !cfg.Prometheus.Enabled {
		return ErrMetricsDisabled
	}

	ms := NewMetricStore()

	if err := ms.Fetch(cfg.Cscli.PrometheusUrl); err != nil {
		return err
	}

	// any section that we don't have in the store is an error
	for _, section := range sections {
		if _, ok := ms[section]; !ok {
			return fmt.Errorf("unknown metrics type: %s", section)
		}
	}

	return ms.Format(color.Output, sections, cfg.Cscli.Output, noUnit)
}

func (cli *cliMetrics) NewCommand() *cobra.Command {
	var (
		url    string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Display crowdsec prometheus metrics.",
		Long:  `Fetch metrics from a Local API server and display them`,
		Example: `# Show all Metrics, skip empty tables (same as "cecli metrics show")
cscli metrics

# Show only some metrics, connect to a different url
cscli metrics --url http://lapi.local:6060/metrics show acquisition parsers

# List available metric types
cscli metrics list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.show(nil, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Prometheus url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(cli.newListCmd())

	return cmd
}

// expandAlias returns a list of sections. The input can be a list of sections or alias.
func (cli *cliMetrics) expandAlias(args []string) []string {
	ret := []string{}

	for _, section := range args {
		switch section {
		case "engine":
			ret = append(ret, "acquisition", "parsers", "scenarios", "stash", "whitelists")
		case "lapi":
			ret = append(ret, "alerts", "decisions", "lapi", "lapi-bouncer", "lapi-decisions", "lapi-machine")
		case "appsec":
			ret = append(ret, "appsec-engine", "appsec-rule")
		default:
			ret = append(ret, section)
		}
	}

	return ret
}

func (cli *cliMetrics) newShowCmd() *cobra.Command {
	var (
		url    string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:   "show [type]...",
		Short: "Display all or part of the available metrics.",
		Long:  `Fetch metrics from a Local API server and display them, optionally filtering on specific types.`,
		Example: `# Show all Metrics, skip empty tables
cscli metrics show

# Use an alias: "engine", "lapi" or "appsec" to show a group of metrics
cscli metrics show engine

# Show some specific metrics, show empty tables, connect to a different url
cscli metrics show acquisition parsers scenarios stash --url http://lapi.local:6060/metrics

# To list available metric types, use "cscli metrics list"
cscli metrics list; cscli metrics list -o json

# Show metrics in json format
cscli metrics show acquisition parsers scenarios stash -o json`,
		// Positional args are optional
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			args = cli.expandAlias(args)
			return cli.show(args, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Metrics url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmd
}

func (cli *cliMetrics) list() error {
	type metricType struct {
		Type        string `json:"type"        yaml:"type"`
		Title       string `json:"title"       yaml:"title"`
		Description string `json:"description" yaml:"description"`
	}

	var allMetrics []metricType

	ms := NewMetricStore()
	for _, section := range maptools.SortedKeys(ms) {
		title, description := ms[section].Description()
		allMetrics = append(allMetrics, metricType{
			Type:        section,
			Title:       title,
			Description: description,
		})
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		t := newTable(color.Output)
		t.SetRowLines(true)
		t.SetHeaders("Type", "Title", "Description")

		for _, metric := range allMetrics {
			t.AddRow(metric.Type, metric.Title, metric.Description)
		}

		t.Render()
	case "json":
		x, err := json.MarshalIndent(allMetrics, "", " ")
		if err != nil {
			return fmt.Errorf("failed to marshal metric types: %w", err)
		}

		fmt.Println(string(x))
	case "raw":
		x, err := yaml.Marshal(allMetrics)
		if err != nil {
			return fmt.Errorf("failed to marshal metric types: %w", err)
		}

		fmt.Println(string(x))
	}

	return nil
}

func (cli *cliMetrics) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "List available types of metrics.",
		Long:              `List available types of metrics.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.list()
		},
	}

	return cmd
}
