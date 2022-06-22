package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/olekukonko/tablewriter"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	"github.com/spf13/cobra"
)

func lapiMetricsToTable(table *tablewriter.Table, stats map[string]map[string]map[string]int) error {

	//stats : machine -> route -> method -> count
	/*we want consistent display order*/
	machineKeys := []string{}
	for k := range stats {
		machineKeys = append(machineKeys, k)
	}
	sort.Strings(machineKeys)

	for _, machine := range machineKeys {
		//oneRow : route -> method -> count
		machineRow := stats[machine]
		for routeName, route := range machineRow {
			for methodName, count := range route {
				row := []string{}
				row = append(row, machine)
				row = append(row, routeName)
				row = append(row, methodName)
				if count != 0 {
					row = append(row, fmt.Sprintf("%d", count))
				} else {
					row = append(row, "-")
				}
				table.Append(row)
			}
		}
	}
	return nil
}

func metricsToTable(table *tablewriter.Table, stats map[string]map[string]int, keys []string) error {

	var sortedKeys []string

	if table == nil {
		return fmt.Errorf("nil table")
	}
	//sort keys to keep consistent order when printing
	sortedKeys = []string{}
	for akey := range stats {
		sortedKeys = append(sortedKeys, akey)
	}
	sort.Strings(sortedKeys)
	//
	for _, alabel := range sortedKeys {
		astats, ok := stats[alabel]
		if !ok {
			continue
		}
		row := []string{}
		row = append(row, alabel) //name
		for _, sl := range keys {
			if v, ok := astats[sl]; ok && v != 0 {
				numberToShow := fmt.Sprintf("%d", v)
				if !noUnit {
					numberToShow = formatNumber(v)
				}
				row = append(row, numberToShow)
			} else {
				row = append(row, "-")
			}
		}
		table.Append(row)
	}
	return nil
}

/*This is a complete rip from prom2json*/
func ShowPrometheus(url string) {
	mfChan := make(chan *dto.MetricFamily, 1024)

	// Start with the DefaultTransport for sane defaults.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Conservatively disable HTTP keep-alives as this program will only
	// ever need a single HTTP request.
	transport.DisableKeepAlives = true
	// Timeout early if the server doesn't even return the headers.
	transport.ResponseHeaderTimeout = time.Minute

	go func() {
		defer types.CatchPanic("crowdsec/ShowPrometheus")
		err := prom2json.FetchMetricFamilies(url, mfChan, transport)
		if err != nil {
			log.Fatalf("failed to fetch prometheus metrics : %v", err)
		}
	}()

	result := []*prom2json.Family{}
	for mf := range mfChan {
		result = append(result, prom2json.NewFamily(mf))
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
				buckets_stats[name]["instanciation"] += ival
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
			default:
				continue
			}

		}
	}
	if csConfig.Cscli.Output == "human" {

		acquisTable := tablewriter.NewWriter(os.Stdout)
		acquisTable.SetHeader([]string{"Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket"})
		keys := []string{"reads", "parsed", "unparsed", "pour"}
		if err := metricsToTable(acquisTable, acquis_stats, keys); err != nil {
			log.Warningf("while collecting acquis stats : %s", err)
		}
		bucketsTable := tablewriter.NewWriter(os.Stdout)
		bucketsTable.SetHeader([]string{"Bucket", "Current Count", "Overflows", "Instantiated", "Poured", "Expired"})
		keys = []string{"curr_count", "overflow", "instanciation", "pour", "underflow"}
		if err := metricsToTable(bucketsTable, buckets_stats, keys); err != nil {
			log.Warningf("while collecting acquis stats : %s", err)
		}

		parsersTable := tablewriter.NewWriter(os.Stdout)
		parsersTable.SetHeader([]string{"Parsers", "Hits", "Parsed", "Unparsed"})
		keys = []string{"hits", "parsed", "unparsed"}
		if err := metricsToTable(parsersTable, parsers_stats, keys); err != nil {
			log.Warningf("while collecting acquis stats : %s", err)
		}

		lapiMachinesTable := tablewriter.NewWriter(os.Stdout)
		lapiMachinesTable.SetHeader([]string{"Machine", "Route", "Method", "Hits"})
		if err := lapiMetricsToTable(lapiMachinesTable, lapi_machine_stats); err != nil {
			log.Warningf("while collecting machine lapi stats : %s", err)
		}

		//lapiMetricsToTable
		lapiBouncersTable := tablewriter.NewWriter(os.Stdout)
		lapiBouncersTable.SetHeader([]string{"Bouncer", "Route", "Method", "Hits"})
		if err := lapiMetricsToTable(lapiBouncersTable, lapi_bouncer_stats); err != nil {
			log.Warningf("while collecting bouncer lapi stats : %s", err)
		}

		lapiDecisionsTable := tablewriter.NewWriter(os.Stdout)
		lapiDecisionsTable.SetHeader([]string{"Bouncer", "Empty answers", "Non-empty answers"})
		for bouncer, hits := range lapi_decisions_stats {
			row := []string{}
			row = append(row, bouncer)
			row = append(row, fmt.Sprintf("%d", hits.Empty))
			row = append(row, fmt.Sprintf("%d", hits.NonEmpty))
			lapiDecisionsTable.Append(row)
		}

		/*unfortunately, we can't reuse metricsToTable as the structure is too different :/*/
		lapiTable := tablewriter.NewWriter(os.Stdout)
		lapiTable.SetHeader([]string{"Route", "Method", "Hits"})
		sortedKeys := []string{}
		for akey := range lapi_stats {
			sortedKeys = append(sortedKeys, akey)
		}
		sort.Strings(sortedKeys)
		for _, alabel := range sortedKeys {
			astats := lapi_stats[alabel]
			subKeys := []string{}
			for skey := range astats {
				subKeys = append(subKeys, skey)
			}
			sort.Strings(subKeys)
			for _, sl := range subKeys {
				row := []string{}
				row = append(row, alabel)
				row = append(row, sl)
				row = append(row, fmt.Sprintf("%d", astats[sl]))
				lapiTable.Append(row)
			}
		}

		decisionsTable := tablewriter.NewWriter(os.Stdout)
		decisionsTable.SetHeader([]string{"Reason", "Origin", "Action", "Count"})
		for reason, origins := range decisions_stats {
			for origin, actions := range origins {
				for action, hits := range actions {
					row := []string{}
					row = append(row, reason)
					row = append(row, origin)
					row = append(row, action)
					row = append(row, fmt.Sprintf("%d", hits))
					decisionsTable.Append(row)
				}
			}
		}

		alertsTable := tablewriter.NewWriter(os.Stdout)
		alertsTable.SetHeader([]string{"Reason", "Count"})
		for scenario, hits := range alerts_stats {
			row := []string{}
			row = append(row, scenario)
			row = append(row, fmt.Sprintf("%d", hits))
			alertsTable.Append(row)
		}

		if bucketsTable.NumLines() > 0 {
			log.Printf("Buckets Metrics:")
			bucketsTable.SetAlignment(tablewriter.ALIGN_LEFT)
			bucketsTable.Render()
		}
		if acquisTable.NumLines() > 0 {
			log.Printf("Acquisition Metrics:")
			acquisTable.SetAlignment(tablewriter.ALIGN_LEFT)
			acquisTable.Render()
		}
		if parsersTable.NumLines() > 0 {
			log.Printf("Parser Metrics:")
			parsersTable.SetAlignment(tablewriter.ALIGN_LEFT)
			parsersTable.Render()
		}
		if lapiTable.NumLines() > 0 {
			log.Printf("Local Api Metrics:")
			lapiTable.SetAlignment(tablewriter.ALIGN_LEFT)
			lapiTable.Render()
		}
		if lapiMachinesTable.NumLines() > 0 {
			log.Printf("Local Api Machines Metrics:")
			lapiMachinesTable.SetAlignment(tablewriter.ALIGN_LEFT)
			lapiMachinesTable.Render()
		}
		if lapiBouncersTable.NumLines() > 0 {
			log.Printf("Local Api Bouncers Metrics:")
			lapiBouncersTable.SetAlignment(tablewriter.ALIGN_LEFT)
			lapiBouncersTable.Render()
		}

		if lapiDecisionsTable.NumLines() > 0 {
			log.Printf("Local Api Bouncers Decisions:")
			lapiDecisionsTable.SetAlignment(tablewriter.ALIGN_LEFT)
			lapiDecisionsTable.Render()
		}

		if decisionsTable.NumLines() > 0 {
			log.Printf("Local Api Decisions:")
			decisionsTable.SetAlignment(tablewriter.ALIGN_LEFT)
			decisionsTable.Render()
		}

		if alertsTable.NumLines() > 0 {
			log.Printf("Local Api Alerts:")
			alertsTable.SetAlignment(tablewriter.ALIGN_LEFT)
			alertsTable.Render()
		}

	} else if csConfig.Cscli.Output == "json" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, lapi_stats, lapi_bouncer_stats, lapi_machine_stats, lapi_decisions_stats, decisions_stats, alerts_stats} {
			x, err := json.MarshalIndent(val, "", " ")
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	} else if csConfig.Cscli.Output == "raw" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, lapi_stats, lapi_bouncer_stats, lapi_machine_stats, lapi_decisions_stats, decisions_stats, alerts_stats} {
			x, err := yaml.Marshal(val)
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	}
}

var noUnit bool

func NewMetricsCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdMetrics = &cobra.Command{
		Use:               "metrics",
		Short:             "Display crowdsec prometheus metrics.",
		Long:              `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := csConfig.LoadPrometheus(); err != nil {
				log.Fatalf(err.Error())
			}
			if !csConfig.Prometheus.Enabled {
				log.Warning("Prometheus is not enabled, can't show metrics")
				os.Exit(1)
			}

			if prometheusURL == "" {
				prometheusURL = csConfig.Cscli.PrometheusUrl
			}

			if prometheusURL == "" {
				log.Errorf("No prometheus url, please specify in %s or via -u", *csConfig.FilePath)
				os.Exit(1)
			}

			ShowPrometheus(prometheusURL + "/metrics")
		},
	}
	cmdMetrics.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url (http://<ip>:<port>/metrics)")
	cmdMetrics.PersistentFlags().BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmdMetrics
}
