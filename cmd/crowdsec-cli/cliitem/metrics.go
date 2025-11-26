package cliitem

import (
	"context"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/climetrics"

)

func showMetrics(ctx context.Context, prometheusURL string, hub *cwhub.Hub, hubItem *cwhub.Item, wantColor string) error {
	switch hubItem.Type {
	case cwhub.PARSERS:
		metrics, err := getParserMetric(ctx, prometheusURL, hubItem.Name)
		if err != nil {
			return err
		}
		parserMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	case cwhub.SCENARIOS:
		metrics, err := getScenarioMetric(ctx, prometheusURL, hubItem.Name)
		if err != nil {
			return err
		}
		scenarioMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	case cwhub.COLLECTIONS:
		for sub := range hubItem.CurrentDependencies().SubItems(hub) {
			if err := showMetrics(ctx, prometheusURL, hub, sub, wantColor); err != nil {
				return err
			}
		}
	case cwhub.APPSEC_RULES:
		metrics, err := getAppsecRuleMetric(ctx, prometheusURL, hubItem.Name)
		if err != nil {
			return err
		}
		appsecMetricsTable(color.Output, wantColor, hubItem.Name, metrics)
	default: // no metrics for this item type
	}

	return nil
}

func getParserMetric(ctx context.Context, url string, itemName string) (map[string]map[string]int, error) {
	stats := make(map[string]map[string]int)

	results, err := climetrics.ScrapeMetrics(ctx, url)
	if err != nil {
		return nil, err
	}

	for _, p := range results {
		if !strings.HasPrefix(p.Name, "cs_") {
			continue
		}

		if p.Labels["name"] != itemName {
			continue
		}

		source, ok := p.Labels["source"]

		if !ok {
			log.Debugf("no source in Metric %v", p.Labels)
		} else {
			if srctype, ok := p.Labels["type"]; ok {
				source = srctype + ":" + source
			}
		}

		if _, ok := stats[source]; !ok {
			stats[source] = make(map[string]int)
		}

		ival := int(p.Value)

		switch p.Name {
		case metrics.GlobalParserHitsOkMetricName:
			stats[source]["parsed"] += ival
		case metrics.GlobalParserHitsKoMetricName:
			stats[source]["unparsed"] += ival
		case metrics.NodesHitsMetricName:
			stats[source]["hits"] += ival
		case metrics.NodesHitsOkMetricName:
			stats[source]["parsed"] += ival
		case metrics.NodesHitsKoMetricName:
			stats[source]["unparsed"] += ival
		default:
			continue
		}
	}

	return stats, nil
}

func getScenarioMetric(ctx context.Context, url string, itemName string) (map[string]int, error) {
	stats := make(map[string]int)

	stats["instantiation"] = 0
	stats["curr_count"] = 0
	stats["overflow"] = 0
	stats["pour"] = 0
	stats["underflow"] = 0

	results, err := climetrics.ScrapeMetrics(ctx, url)
	if err != nil {
		return nil, err
	}

	for _, p := range results {
		if !strings.HasPrefix(p.Name, "cs_") {
			continue
		}

		if p.Labels["name"] != itemName {
			continue
		}

		ival := int(p.Value)

		switch p.Name {
		case metrics.BucketsInstantiationMetricName:
			stats["instantiation"] += ival
		case metrics.BucketsCurrentCountMetricName:
			stats["curr_count"] += ival
		case metrics.BucketsOverflowMetricName:
			stats["overflow"] += ival
		case metrics.BucketPouredMetricName:
			stats["pour"] += ival
		case metrics.BucketsUnderflowMetricName:
			stats["underflow"] += ival
		default:
			continue
		}
	}

	return stats, nil
}

func getAppsecRuleMetric(ctx context.Context, url string, itemName string) (map[string]int, error) {
	stats := make(map[string]int)

	stats["inband_hits"] = 0
	stats["outband_hits"] = 0

	results, err := climetrics.ScrapeMetrics(ctx, url)
	if err != nil {
		return nil, err
	}

	for _, p := range results {
		if !strings.HasPrefix(p.Name, "cs_") {
			continue
		}

		if p.Labels["name"] != itemName {
			continue
		}

		band, ok := p.Labels["type"]
		if !ok {
			log.Debugf("no type in Metric %v", p.Labels)
		}

		ival := int(p.Value)

		switch p.Name {
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

	return stats, nil
}
