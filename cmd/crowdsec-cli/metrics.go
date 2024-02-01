package main

import (
	"encoding/json"
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

	"github.com/crowdsecurity/go-cs-lib/trace"
)

type (
	statAcquis map[string]map[string]int
	statParser map[string]map[string]int
	statBucket map[string]map[string]int
	statLapi map[string]map[string]int
	statLapiMachine map[string]map[string]map[string]int
	statLapiBouncer map[string]map[string]map[string]int
	statLapiDecision map[string]struct {
		NonEmpty int
		Empty    int
	}
	statDecision map[string]map[string]map[string]int
	statAppsecEngine map[string]map[string]int
	statAppsecRule map[string]map[string]map[string]int
	statAlert map[string]int
	statStash map[string]struct {
		Type  string
		Count int
	}
)

type metricSection interface {
	Table(io.Writer, bool)
}

type metricStore map[string]metricSection

var metricSections = []string{
	"acquisition",
	"buckets",
	"parsers",
	"lapi",
	"lapi_machine",
	"lapi_bouncer",
	"lapi_decisions",
	"decisions",
	"alerts",
	"stash",
	"appsec_engine",
	"appsec_rule",
}

func NewMetricStore(url string) (metricStore, error) {
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
			errChan <- fmt.Errorf("failed to fetch prometheus metrics: %w", err)
			return
		}
		errChan <- nil
	}()

	result := []*prom2json.Family{}
	for mf := range mfChan {
		result = append(result, prom2json.NewFamily(mf))
	}

	if err := <-errChan; err != nil {
		return nil, err
	}

	log.Debugf("Finished reading prometheus output, %d entries", len(result))
	/*walk*/

	mAcquis := statAcquis{}
	mParser := statParser{}
	mBucket := statBucket{}
	mLapi := statLapi{}
	mLapiMachine := statLapiMachine{}
	mLapiBouncer := statLapiBouncer{}
	mLapiDecision := statLapiDecision{}
	mDecision := statDecision{}
	mAppsecEngine := statAppsecEngine{}
	mAppsecRule := statAppsecRule{}
	mAlert := statAlert{}
	mStash := statStash{}

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

			mtype := metric.Labels["type"]

			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
			}
			ival := int(fval)
			switch fam.Name {
			/*buckets*/
			case "cs_bucket_created_total":
				if _, ok := mBucket[name]; !ok {
					mBucket[name] = make(map[string]int)
				}
				mBucket[name]["instantiation"] += ival
			case "cs_buckets":
				if _, ok := mBucket[name]; !ok {
					mBucket[name] = make(map[string]int)
				}
				mBucket[name]["curr_count"] += ival
			case "cs_bucket_overflowed_total":
				if _, ok := mBucket[name]; !ok {
					mBucket[name] = make(map[string]int)
				}
				mBucket[name]["overflow"] += ival
			case "cs_bucket_poured_total":
				if _, ok := mBucket[name]; !ok {
					mBucket[name] = make(map[string]int)
				}
				if _, ok := mAcquis[source]; !ok {
					mAcquis[source] = make(map[string]int)
				}
				mBucket[name]["pour"] += ival
				mAcquis[source]["pour"] += ival
			case "cs_bucket_underflowed_total":
				if _, ok := mBucket[name]; !ok {
					mBucket[name] = make(map[string]int)
				}
				mBucket[name]["underflow"] += ival
				/*acquis*/
			case "cs_parser_hits_total":
				if _, ok := mAcquis[source]; !ok {
					mAcquis[source] = make(map[string]int)
				}
				mAcquis[source]["reads"] += ival
			case "cs_parser_hits_ok_total":
				if _, ok := mAcquis[source]; !ok {
					mAcquis[source] = make(map[string]int)
				}
				mAcquis[source]["parsed"] += ival
			case "cs_parser_hits_ko_total":
				if _, ok := mAcquis[source]; !ok {
					mAcquis[source] = make(map[string]int)
				}
				mAcquis[source]["unparsed"] += ival
			case "cs_node_hits_total":
				if _, ok := mParser[name]; !ok {
					mParser[name] = make(map[string]int)
				}
				mParser[name]["hits"] += ival
			case "cs_node_hits_ok_total":
				if _, ok := mParser[name]; !ok {
					mParser[name] = make(map[string]int)
				}
				mParser[name]["parsed"] += ival
			case "cs_node_hits_ko_total":
				if _, ok := mParser[name]; !ok {
					mParser[name] = make(map[string]int)
				}
				mParser[name]["unparsed"] += ival
			case "cs_lapi_route_requests_total":
				if _, ok := mLapi[route]; !ok {
					mLapi[route] = make(map[string]int)
				}
				mLapi[route][method] += ival
			case "cs_lapi_machine_requests_total":
				if _, ok := mLapiMachine[machine]; !ok {
					mLapiMachine[machine] = make(map[string]map[string]int)
				}
				if _, ok := mLapiMachine[machine][route]; !ok {
					mLapiMachine[machine][route] = make(map[string]int)
				}
				mLapiMachine[machine][route][method] += ival
			case "cs_lapi_bouncer_requests_total":
				if _, ok := mLapiBouncer[bouncer]; !ok {
					mLapiBouncer[bouncer] = make(map[string]map[string]int)
				}
				if _, ok := mLapiBouncer[bouncer][route]; !ok {
					mLapiBouncer[bouncer][route] = make(map[string]int)
				}
				mLapiBouncer[bouncer][route][method] += ival
			case "cs_lapi_decisions_ko_total", "cs_lapi_decisions_ok_total":
				if _, ok := mLapiDecision[bouncer]; !ok {
					mLapiDecision[bouncer] = struct {
						NonEmpty int
						Empty    int
					}{}
				}
				x := mLapiDecision[bouncer]
				if fam.Name == "cs_lapi_decisions_ko_total" {
					x.Empty += ival
				} else if fam.Name == "cs_lapi_decisions_ok_total" {
					x.NonEmpty += ival
				}
				mLapiDecision[bouncer] = x
			case "cs_active_decisions":
				if _, ok := mDecision[reason]; !ok {
					mDecision[reason] = make(map[string]map[string]int)
				}
				if _, ok := mDecision[reason][origin]; !ok {
					mDecision[reason][origin] = make(map[string]int)
				}
				mDecision[reason][origin][action] += ival
			case "cs_alerts":
				/*if _, ok := mAlert[scenario]; !ok {
					mAlert[scenario] = make(map[string]int)
				}*/
				mAlert[reason] += ival
			case "cs_cache_size":
				mStash[name] = struct {
					Type  string
					Count int
				}{Type: mtype, Count: ival}
			case "cs_appsec_reqs_total":
				if _, ok := mAppsecEngine[metric.Labels["appsec_engine"]]; !ok {
					mAppsecEngine[metric.Labels["appsec_engine"]] = make(map[string]int, 0)
				}
				mAppsecEngine[metric.Labels["appsec_engine"]]["processed"] = ival
			case "cs_appsec_block_total":
				if _, ok := mAppsecEngine[metric.Labels["appsec_engine"]]; !ok {
					mAppsecEngine[metric.Labels["appsec_engine"]] = make(map[string]int, 0)
				}
				mAppsecEngine[metric.Labels["appsec_engine"]]["blocked"] = ival
			case "cs_appsec_rule_hits":
				appsecEngine := metric.Labels["appsec_engine"]
				ruleID := metric.Labels["rule_name"]
				if _, ok := mAppsecRule[appsecEngine]; !ok {
					mAppsecRule[appsecEngine] = make(map[string]map[string]int, 0)
				}
				if _, ok := mAppsecRule[appsecEngine][ruleID]; !ok {
					mAppsecRule[appsecEngine][ruleID] = make(map[string]int, 0)
				}
				mAppsecRule[appsecEngine][ruleID]["triggered"] = ival
			default:
				log.Debugf("unknown: %+v", fam.Name)
				continue
			}
		}
	}

	return metricStore{
		"acquisition": mAcquis,
		"buckets": mBucket,
		"parsers": mParser,
		"lapi": mLapi,
		"lapi_machine": mLapiMachine,
		"lapi_bouncer": mLapiBouncer,
		"lapi_decisions": mLapiDecision,
		"decisions": mDecision,
		"alerts": mAlert,
		"stash": mStash,
		"appsec_engine": mAppsecEngine,
		"appsec_rule": mAppsecRule,
	}, nil
}

type cliMetrics struct {
	cfg configGetter
}

func NewCLIMetrics(getconfig configGetter) *cliMetrics {
	return &cliMetrics{
		cfg: getconfig,
	}
}

func (ms metricStore) Format(out io.Writer, sections []string, formatType string, noUnit bool) error {
	// copy only the sections we want
	want := map[string]metricSection{}

	if len(sections) == 0 {
		sections = metricSections
	}

	for _, section := range sections {
		want[section] = ms[section]
	}

	switch formatType {
	case "human":
		for section := range want {
			want[section].Table(out, noUnit)
		}
	case "json":
		x, err := json.MarshalIndent(want, "", " ")
		if err != nil {
			return fmt.Errorf("failed to unmarshal metrics : %v", err)
		}
		out.Write(x)
	case "raw":
		x, err := yaml.Marshal(want)
		if err != nil {
			return fmt.Errorf("failed to unmarshal metrics : %v", err)
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
		return fmt.Errorf("prometheus section missing, can't show metrics")
	}

	if !cfg.Prometheus.Enabled {
		return fmt.Errorf("prometheus is not enabled, can't show metrics")
	}

	ms, err := NewMetricStore(cfg.Cscli.PrometheusUrl)
	if err != nil {
		return err
	}

	if err := ms.Format(color.Output, sections, cfg.Cscli.Output, noUnit); err != nil {
		return err
	}
	return nil
}

func (cli *cliMetrics) NewCommand() *cobra.Command {
	var (
		url string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:               "metrics",
		Short:             "Display crowdsec prometheus metrics.",
		Long:              `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
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

func (cli *cliMetrics) newShowCmd() *cobra.Command {
	var (
		url string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:               "show [section]...",
		Short:             "Display crowdsec prometheus metrics.",
		Long:              `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.show(args, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Prometheus url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmd
}

func (cli *cliMetrics) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "List available sections for metrics.",
		Long:              `List available sections for metrics.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, section := range metricSections {
				fmt.Println(section)
			}
			return nil
		},
	}

	return cmd
}
