package clihub

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func showMetrics(prometheusURL string, hubItem *cwhub.Item, wantColor string) error {
	switch hubItem.Type {
	case cwhub.PARSERS:
		metrics := getParserMetric(prometheusURL, hubItem.Name)
		parserMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	case cwhub.SCENARIOS:
		metrics := getScenarioMetric(prometheusURL, hubItem.Name)
		scenarioMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	case cwhub.COLLECTIONS:
		for _, sub := range hubItem.SubItems() {
			if err := showMetrics(prometheusURL, sub, wantColor); err != nil {
				return err
			}
		}
	case cwhub.APPSEC_RULES:
		metrics := getAppsecRuleMetric(prometheusURL, hubItem.Name)
		appsecMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	default: // no metrics for this item type
	}

	return nil
}

// getParserMetric is a complete rip from prom2json
func getParserMetric(url string, itemName string) map[string]map[string]int {
	stats := make(map[string]map[string]int)

	result := getPrometheusMetric(url)
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

			if name != itemName {
				continue
			}

			source, ok := metric.Labels["source"]

			if !ok {
				log.Debugf("no source in Metric %v", metric.Labels)
			} else {
				if srctype, ok := metric.Labels["type"]; ok {
					source = srctype + ":" + source
				}
			}

			value := m.(prom2json.Metric).Value

			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
				continue
			}

			ival := int(fval)

			switch fam.Name {
			case "cs_reader_hits_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
					stats[source]["parsed"] = 0
					stats[source]["reads"] = 0
					stats[source]["unparsed"] = 0
					stats[source]["hits"] = 0
				}
				stats[source]["reads"] += ival
			case "cs_parser_hits_ok_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["parsed"] += ival
			case "cs_parser_hits_ko_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["unparsed"] += ival
			case "cs_node_hits_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["hits"] += ival
			case "cs_node_hits_ok_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["parsed"] += ival
			case "cs_node_hits_ko_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["unparsed"] += ival
			default:
				continue
			}
		}
	}

	return stats
}

func getScenarioMetric(url string, itemName string) map[string]int {
	stats := make(map[string]int)

	stats["instantiation"] = 0
	stats["curr_count"] = 0
	stats["overflow"] = 0
	stats["pour"] = 0
	stats["underflow"] = 0

	result := getPrometheusMetric(url)
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

			if name != itemName {
				continue
			}

			value := m.(prom2json.Metric).Value

			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
				continue
			}

			ival := int(fval)

			switch fam.Name {
			case "cs_bucket_created_total":
				stats["instantiation"] += ival
			case "cs_buckets":
				stats["curr_count"] += ival
			case "cs_bucket_overflowed_total":
				stats["overflow"] += ival
			case "cs_bucket_poured_total":
				stats["pour"] += ival
			case "cs_bucket_underflowed_total":
				stats["underflow"] += ival
			default:
				continue
			}
		}
	}

	return stats
}

func getAppsecRuleMetric(url string, itemName string) map[string]int {
	stats := make(map[string]int)

	stats["inband_hits"] = 0
	stats["outband_hits"] = 0

	results := getPrometheusMetric(url)
	for idx, fam := range results {
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

			name, ok := metric.Labels["rule_name"]

			if !ok {
				log.Debugf("no rule_name in Metric %v", metric.Labels)
			}

			if name != itemName {
				continue
			}

			band, ok := metric.Labels["type"]
			if !ok {
				log.Debugf("no type in Metric %v", metric.Labels)
			}

			value := m.(prom2json.Metric).Value

			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
				continue
			}

			ival := int(fval)

			switch fam.Name {
			case "cs_appsec_rule_hits":
				switch band {
				case "inband":
					stats["inband_hits"] += ival
				case "outband":
					stats["outband_hits"] += ival
				default:
					continue
				}
			default:
				continue
			}
		}
	}

	return stats
}

func getPrometheusMetric(url string) []*prom2json.Family {
	mfChan := make(chan *dto.MetricFamily, 1024)

	// Start with the DefaultTransport for sane defaults.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Conservatively disable HTTP keep-alives as this program will only
	// ever need a single HTTP request.
	transport.DisableKeepAlives = true
	// Timeout early if the server doesn't even return the headers.
	transport.ResponseHeaderTimeout = time.Minute

	go func() {
		defer trace.CatchPanic("crowdsec/GetPrometheusMetric")

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

	return result
}
