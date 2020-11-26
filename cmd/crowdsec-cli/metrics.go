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

func apilMetricsToTable(table *tablewriter.Table, stats map[string]map[string]map[string]int) error {

	//stats : machine -> route -> method -> count
	/*we want consistant display order*/
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
				row = append(row, fmt.Sprintf("%d", v))
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
	apil_decisions_stats := map[string]struct {
		NonEmpty int
		Empty    int
	}{}
	acquis_stats := map[string]map[string]int{}
	parsers_stats := map[string]map[string]int{}
	buckets_stats := map[string]map[string]int{}
	apil_stats := map[string]map[string]int{}
	apil_machine_stats := map[string]map[string]map[string]int{}
	apil_bouncer_stats := map[string]map[string]map[string]int{}

	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Tracef("round %d", idx)
		for _, m := range fam.Metrics {
			metric := m.(prom2json.Metric)
			name, ok := metric.Labels["name"]
			if !ok {
				log.Debugf("no name in Metric %v", metric.Labels)
			}
			source, ok := metric.Labels["source"]
			if !ok {
				log.Debugf("no source in Metric %v", metric.Labels)
			}
			value := m.(prom2json.Metric).Value
			machine := metric.Labels["machine"]
			bouncer := metric.Labels["bouncer"]

			route := metric.Labels["route"]
			method := metric.Labels["method"]

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
			case "cs_reader_hits_total":
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
			case "cs_apil_route_requests_total":
				if _, ok := apil_stats[route]; !ok {
					apil_stats[route] = make(map[string]int)
				}
				apil_stats[route][method] += ival
			case "cs_apil_machine_requests_total":
				if _, ok := apil_machine_stats[machine]; !ok {
					apil_machine_stats[machine] = make(map[string]map[string]int)
				}
				if _, ok := apil_machine_stats[machine][route]; !ok {
					apil_machine_stats[machine][route] = make(map[string]int)
				}
				apil_machine_stats[machine][route][method] += ival
			case "cs_apil_bouncer_requests_total":
				if _, ok := apil_bouncer_stats[bouncer]; !ok {
					apil_bouncer_stats[bouncer] = make(map[string]map[string]int)
				}
				if _, ok := apil_bouncer_stats[bouncer][route]; !ok {
					apil_bouncer_stats[bouncer][route] = make(map[string]int)
				}
				apil_bouncer_stats[bouncer][route][method] += ival
			case "cs_apil_decisions_ko_total":
				if _, ok := apil_decisions_stats[bouncer]; !ok {
					apil_decisions_stats[bouncer] = struct {
						NonEmpty int
						Empty    int
					}{}
				}
				x := apil_decisions_stats[bouncer]
				x.Empty += ival
				apil_decisions_stats[bouncer] = x
			case "cs_apil_decisions_ok_total":
				if _, ok := apil_decisions_stats[bouncer]; !ok {
					apil_decisions_stats[bouncer] = struct {
						NonEmpty int
						Empty    int
					}{}
				}
				x := apil_decisions_stats[bouncer]
				x.NonEmpty += ival
				apil_decisions_stats[bouncer] = x
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
		bucketsTable.SetHeader([]string{"Bucket", "Current Count", "Overflows", "Instanciated", "Poured", "Expired"})
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

		apilMachinesTable := tablewriter.NewWriter(os.Stdout)
		apilMachinesTable.SetHeader([]string{"Machine", "Route", "Method", "Hits"})
		if err := apilMetricsToTable(apilMachinesTable, apil_machine_stats); err != nil {
			log.Warningf("while collecting machine apil stats : %s", err)
		}

		//apilMetricsToTable
		apilBouncersTable := tablewriter.NewWriter(os.Stdout)
		apilBouncersTable.SetHeader([]string{"Bouncer", "Route", "Method", "Hits"})
		if err := apilMetricsToTable(apilBouncersTable, apil_bouncer_stats); err != nil {
			log.Warningf("while collecting bouncer apil stats : %s", err)
		}

		apilDecisionsTable := tablewriter.NewWriter(os.Stdout)
		apilDecisionsTable.SetHeader([]string{"Bouncer", "Empty answers", "Non-empty answers"})
		for bouncer, hits := range apil_decisions_stats {
			row := []string{}
			row = append(row, bouncer)
			row = append(row, fmt.Sprintf("%d", hits.Empty))
			row = append(row, fmt.Sprintf("%d", hits.NonEmpty))
			apilDecisionsTable.Append(row)
		}

		/*unfortunately, we can't reuse metricsToTable as the structure is too different :/*/
		apilTable := tablewriter.NewWriter(os.Stdout)
		apilTable.SetHeader([]string{"Route", "Method", "Hits"})
		sortedKeys := []string{}
		for akey := range apil_stats {
			sortedKeys = append(sortedKeys, akey)
		}
		sort.Strings(sortedKeys)
		for _, alabel := range sortedKeys {
			astats := apil_stats[alabel]
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
				apilTable.Append(row)
			}
		}

		if bucketsTable.NumLines() > 0 {
			log.Printf("Buckets Metrics:")
			bucketsTable.Render()
		}
		if acquisTable.NumLines() > 0 {
			log.Printf("Acquisition Metrics:")
			acquisTable.Render()
		}
		if parsersTable.NumLines() > 0 {
			log.Printf("Parser Metrics:")
			parsersTable.Render()
		}
		if apilTable.NumLines() > 0 {
			log.Printf("Local Api Metrics:")
			apilTable.Render()
		}
		if apilMachinesTable.NumLines() > 0 {
			log.Printf("Local Api Machines Metrics:")
			apilMachinesTable.Render()
		}
		if apilBouncersTable.NumLines() > 0 {
			log.Printf("Local Api Bouncers Metrics:")
			apilBouncersTable.Render()
		}

		if apilDecisionsTable.NumLines() > 0 {
			log.Printf("Local Api Bouncers Decisions:")
			apilDecisionsTable.Render()
		}

	} else if csConfig.Cscli.Output == "json" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, apil_stats, apil_bouncer_stats, apil_machine_stats, apil_decisions_stats} {
			x, err := json.MarshalIndent(val, "", " ")
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	} else if csConfig.Cscli.Output == "raw" {
		for _, val := range []interface{}{acquis_stats, parsers_stats, buckets_stats, apil_stats, apil_bouncer_stats, apil_machine_stats, apil_decisions_stats} {
			x, err := yaml.Marshal(val)
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	}
}

func NewMetricsCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdMetrics = &cobra.Command{
		Use:   "metrics",
		Short: "Display crowdsec prometheus metrics.",
		Long:  `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			ShowPrometheus(prometheusURL)
		},
	}
	cmdMetrics.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")

	return cmdMetrics
}
