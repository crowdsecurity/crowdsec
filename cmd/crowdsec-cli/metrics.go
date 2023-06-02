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
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"
)

// FormatPrometheusMetrics is a complete rip from prom2json
func FormatPrometheusMetrics(out io.Writer, url string, formatType string) error {
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
		return err
	}

	log.Debugf("Finished reading prometheus output, %d entries", len(result))
	/*walk*/
	lapi_decisions_stats := map[string]struct {
		NonEmpty int
		Empty    int
	}{}
	acquis_stats := map[string]map[string]int{}
	parsers_stats := map[string]map[string]int{}
	buckets_stats := map[string]map[string]int{}
	lapi_stats := map[string]map[string]int{}
	lapi_machine_stats := map[string]map[string]map[string]int{}
	lapi_bouncer_stats := map[string]map[string]map[string]int{}
	decisions_stats := map[string]map[string]map[string]int{}
	alerts_stats := map[string]int{}
	stash_stats := map[string]struct {
		Type  string
		Count int
	}{}

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
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["instantiation"] += ival
			case "cs_buckets":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["curr_count"] += ival
			case "cs_bucket_overflowed_total":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["overflow"] += ival
			case "cs_bucket_poured_total":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				buckets_stats[name]["pour"] += ival
				acquis_stats[source]["pour"] += ival
			case "cs_bucket_underflowed_total":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["underflow"] += ival
				/*acquis*/
			case "cs_parser_hits_total":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["reads"] += ival
			case "cs_parser_hits_ok_total":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["parsed"] += ival
			case "cs_parser_hits_ko_total":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["unparsed"] += ival
			case "cs_node_hits_total":
				if _, ok := parsers_stats[name]; !ok {
					parsers_stats[name] = make(map[string]int)
				}
				parsers_stats[name]["hits"] += ival
			case "cs_node_hits_ok_total":
				if _, ok := parsers_stats[name]; !ok {
					parsers_stats[name] = make(map[string]int)
				}
				parsers_stats[name]["parsed"] += ival
			case "cs_node_hits_ko_total":
				if _, ok := parsers_stats[name]; !ok {
					parsers_stats[name] = make(map[string]int)
				}
				parsers_stats[name]["unparsed"] += ival
			case "cs_lapi_route_requests_total":
				if _, ok := lapi_stats[route]; !ok {
					lapi_stats[route] = make(map[string]int)
				}
				lapi_stats[route][method] += ival
			case "cs_lapi_machine_requests_total":
				if _, ok := lapi_machine_stats[machine]; !ok {
					lapi_machine_stats[machine] = make(map[string]map[string]int)
				}
				if _, ok := lapi_machine_stats[machine][route]; !ok {
					lapi_machine_stats[machine][route] = make(map[string]int)
				}
				lapi_machine_stats[machine][route][method] += ival
			case "cs_lapi_bouncer_requests_total":
				if _, ok := lapi_bouncer_stats[bouncer]; !ok {
					lapi_bouncer_stats[bouncer] = make(map[string]map[string]int)
				}
				if _, ok := lapi_bouncer_stats[bouncer][route]; !ok {
					lapi_bouncer_stats[bouncer][route] = make(map[string]int)
				}
				lapi_bouncer_stats[bouncer][route][method] += ival
			case "cs_lapi_decisions_ko_total", "cs_lapi_decisions_ok_total":
				if _, ok := lapi_decisions_stats[bouncer]; !ok {
					lapi_decisions_stats[bouncer] = struct {
						NonEmpty int
						Empty    int
					}{}
				}
				x := lapi_decisions_stats[bouncer]
				if fam.Name == "cs_lapi_decisions_ko_total" {
					x.Empty += ival
				} else if fam.Name == "cs_lapi_decisions_ok_total" {
					x.NonEmpty += ival
				}
				lapi_decisions_stats[bouncer] = x
			case "cs_active_decisions":
				if _, ok := decisions_stats[reason]; !ok {
					decisions_stats[reason] = make(map[string]map[string]int)
				}
				if _, ok := decisions_stats[reason][origin]; !ok {
					decisions_stats[reason][origin] = make(map[string]int)
				}
				decisions_stats[reason][origin][action] += ival
			case "cs_alerts":
				/*if _, ok := alerts_stats[scenario]; !ok {
					alerts_stats[scenario] = make(map[string]int)
				}*/
				alerts_stats[reason] += ival
			case "cs_cache_size":
				stash_stats[name] = struct {
					Type  string
					Count int
				}{Type: mtype, Count: ival}
			default:
				continue
			}

		}
	}

	if formatType == "human" {
		acquisStatsTable(out, acquis_stats)
		bucketStatsTable(out, buckets_stats)
		parserStatsTable(out, parsers_stats)
		lapiStatsTable(out, lapi_stats)
		lapiMachineStatsTable(out, lapi_machine_stats)
		lapiBouncerStatsTable(out, lapi_bouncer_stats)
		lapiDecisionStatsTable(out, lapi_decisions_stats)
		decisionStatsTable(out, decisions_stats)
		alertStatsTable(out, alerts_stats)
		stashStatsTable(out, stash_stats)
	} else if formatType == "json" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, lapi_stats, lapi_bouncer_stats, lapi_machine_stats, lapi_decisions_stats, decisions_stats, alerts_stats, stash_stats} {
			x, err := json.MarshalIndent(val, "", " ")
			if err != nil {
				return fmt.Errorf("failed to unmarshal metrics : %v", err)
			}
			out.Write(x)
		}
		return nil

	} else if formatType == "raw" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, lapi_stats, lapi_bouncer_stats, lapi_machine_stats, lapi_decisions_stats, decisions_stats, alerts_stats, stash_stats} {
			x, err := yaml.Marshal(val)
			if err != nil {
				return fmt.Errorf("failed to unmarshal metrics : %v", err)
			}
			out.Write(x)
		}
		return nil
	}
	return nil
}

var noUnit bool


func runMetrics(cmd *cobra.Command, args []string) error {
	if err := csConfig.LoadPrometheus(); err != nil {
		return fmt.Errorf("failed to load prometheus config: %w", err)
	}

	if csConfig.Prometheus == nil {
		return fmt.Errorf("prometheus section missing, can't show metrics")
	}

	if !csConfig.Prometheus.Enabled {
		return fmt.Errorf("prometheus is not enabled, can't show metrics")
	}

	if prometheusURL == "" {
		prometheusURL = csConfig.Cscli.PrometheusUrl
	}

	if prometheusURL == "" {
		return fmt.Errorf("no prometheus url, please specify in %s or via -u", *csConfig.FilePath)
	}

	err := FormatPrometheusMetrics(color.Output, prometheusURL+"/metrics", csConfig.Cscli.Output)
	if err != nil {
		return fmt.Errorf("could not fetch prometheus metrics: %w", err)
	}
	return nil
}


func NewMetricsCmd() *cobra.Command {
	cmdMetrics := &cobra.Command{
		Use:               "metrics",
		Short:             "Display crowdsec prometheus metrics.",
		Long:              `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: runMetrics,
	}
	cmdMetrics.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url (http://<ip>:<port>/metrics)")
	cmdMetrics.PersistentFlags().BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmdMetrics
}
