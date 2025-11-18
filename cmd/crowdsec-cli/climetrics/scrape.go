package climetrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/common/expfmt"
	dto "github.com/prometheus/client_model/go"
)

type MetricPoint struct {
	Labels map[string]string
	Value  float64
	Type   dto.MetricType
	Name   string
}

// parseMetrics is a helper intended as a lightweight replacement for the prom2json
// package inside cscli.
//
// Only counter, gauge and untyped metrics are returned.
// Aggregation and unit convversions are left to the caller.
func parseMetrics(r io.Reader) ([]MetricPoint, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	mfs, err := parser.TextToMetricFamilies(r)
	
	if err != nil {
		return nil, err
	}

	var out []MetricPoint
	for name, mf := range mfs {
		for _, m := range mf.GetMetric() {
			point := MetricPoint{
				Labels: make(map[string]string),
				Type:   mf.GetType(),
				Name:   name,
			}

			for _, lp := range m.GetLabel() {
				point.Labels[lp.GetName()] = lp.GetValue()
			}

			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				point.Value = m.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				point.Value = m.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				point.Value = m.GetUntyped().GetValue()
			default:
				continue // skip histograms/summaries, we don't have them in cscli
			}

			out = append(out, point)
		}
	}

	return out, nil
}

// ScrapeMetrics retrieves and parses Prometheus metrics from the given URL
// using the provided context for cancellation and timeout.
func ScrapeMetrics(ctx context.Context, url string) ([]MetricPoint, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metrics: %w", err)
	}
	defer resp.Body.Close()

	points, err := parseMetrics(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing metrics: %w", err)
	}

	return points, nil
}
