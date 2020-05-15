package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
				log.Debugf("no name in Metric")
			}
			source, ok := metric.Labels["source"]
			if !ok {
				log.Debugf("no source in Metric")
			}
			value := m.(prom2json.Metric).Value
			ival, err := strconv.Atoi(value)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
			}
			switch fam.Name {
			/*buckets*/
			case "cs_bucket_create":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["instanciation"] += ival
			case "cs_bucket_overflow":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["overflow"] += ival
			case "cs_bucket_pour":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				buckets_stats[name]["pour"] += ival
				acquis_stats[source]["pour"] += ival
			case "cs_bucket_underflow":
				if _, ok := buckets_stats[name]; !ok {
					buckets_stats[name] = make(map[string]int)
				}
				buckets_stats[name]["underflow"] += ival
				/*acquis*/
			case "cs_reader_hits":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["reads"] += ival
			case "cs_parser_hits_ok":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["parsed"] += ival
			case "cs_parser_hits_ko":
				if _, ok := acquis_stats[source]; !ok {
					acquis_stats[source] = make(map[string]int)
				}
				acquis_stats[source]["unparsed"] += ival
			case "cs_node_hits":
				if _, ok := parsers_stats[name]; !ok {
					parsers_stats[name] = make(map[string]int)
				}
				parsers_stats[name]["hits"] += ival
			case "cs_node_hits_ok":
				if _, ok := parsers_stats[name]; !ok {
					parsers_stats[name] = make(map[string]int)
				}
				parsers_stats[name]["parsed"] += ival
			default:
				continue
			}

		}
	}
	if config.output == "human" {
		atable := tablewriter.NewWriter(os.Stdout)
		atable.SetHeader([]string{"Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket"})
		for alabel, astats := range acquis_stats {

			if alabel == "" {
				continue
			}
			row := []string{}
			row = append(row, alabel) //name
			for _, sl := range []string{"reads", "parsed", "unparsed", "pour"} {
				if v, ok := astats[sl]; ok {
					row = append(row, fmt.Sprintf("%d", v))
				} else {
					row = append(row, "-")
				}
			}
			atable.Append(row)
		}
		btable := tablewriter.NewWriter(os.Stdout)
		btable.SetHeader([]string{"Bucket", "Overflows", "Instanciated", "Poured", "Expired"})
		for blabel, bstats := range buckets_stats {
			if blabel == "" {
				continue
			}
			row := []string{}
			row = append(row, blabel) //name
			for _, sl := range []string{"overflow", "instanciation", "pour", "underflow"} {
				if v, ok := bstats[sl]; ok {
					row = append(row, fmt.Sprintf("%d", v))
				} else {
					row = append(row, "-")
				}
			}
			btable.Append(row)
		}
		ptable := tablewriter.NewWriter(os.Stdout)
		ptable.SetHeader([]string{"Parsers", "Hits", "Parsed", "Unparsed"})
		for plabel, pstats := range parsers_stats {
			if plabel == "" {
				continue
			}
			row := []string{}
			row = append(row, plabel) //name
			hits := 0
			parsed := 0
			for _, sl := range []string{"hits", "parsed"} {
				if v, ok := pstats[sl]; ok {
					row = append(row, fmt.Sprintf("%d", v))
					if sl == "hits" {
						hits = v
					} else if sl == "parsed" {
						parsed = v
					}
				} else {
					row = append(row, "-")
				}
			}
			row = append(row, fmt.Sprintf("%d", hits-parsed))
			ptable.Append(row)
		}
		log.Printf("Buckets Metrics:")
		btable.Render() // Send output
		log.Printf("Acquisition Metrics:")
		atable.Render() // Send output
		log.Printf("Parser Metrics:")
		ptable.Render() // Send output
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
