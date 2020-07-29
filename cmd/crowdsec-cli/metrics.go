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

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/olekukonko/tablewriter"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	"github.com/spf13/cobra"
)

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
	acquis_stats := map[string]map[string]int{}
	parsers_stats := map[string]map[string]int{}
	buckets_stats := map[string]map[string]int{}
	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Debugf("round %d", idx)
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
			default:
				continue
			}

		}
	}
	if config.output == "human" {

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

		log.Printf("Buckets Metrics:")
		bucketsTable.Render()
		log.Printf("Acquisition Metrics:")
		acquisTable.Render()
		log.Printf("Parser Metrics:")
		parsersTable.Render()
	} else if config.output == "json" {
		for _, val := range []map[string]map[string]int{acquis_stats, parsers_stats, buckets_stats} {
			x, err := json.MarshalIndent(val, "", " ")
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	} else if config.output == "raw" {
		for _, val := range []map[string]map[string]int{acquis_stats, parsers_stats, buckets_stats} {
			x, err := yaml.Marshal(val)
			if err != nil {
				log.Fatalf("failed to unmarshal metrics : %v", err)
			}
			fmt.Printf("%s\n", string(x))
		}
	}
}

var purl string

func NewMetricsCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdMetrics = &cobra.Command{
		Use:   "metrics",
		Short: "Display crowdsec prometheus metrics.",
		Long:  `Fetch metrics from the prometheus server and display them in a human-friendly way`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			ShowPrometheus(purl)
		},
	}
	cmdMetrics.PersistentFlags().StringVarP(&purl, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")

	return cmdMetrics
}
