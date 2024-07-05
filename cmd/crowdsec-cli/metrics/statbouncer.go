package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// un-aggregated data, de-normalized.
type bouncerMetricItem struct {
	bouncerName string
	ipType      string
	origin      string
	name        string
	unit        string
	value       float64
}

type statBouncer struct {
	// we keep de-normalized metrics so we can iterate
	// over them multiple times and keep the aggregation code simple
	rawMetrics []bouncerMetricItem
	aggregated map[string]map[string]map[string]int64
}

func (s *statBouncer) Description() (string, string) {
	return "Bouncer Metrics",
		`Network traffic blocked by bouncers.`
}

func (s *statBouncer) Fetch(ctx context.Context, db *database.Client) error {
	if db == nil {
		return nil
	}

	// query all bouncer metrics that have not been flushed

	metrics, err := db.Ent.Metric.Query().
		Where(
			metric.GeneratedTypeEQ(metric.GeneratedTypeRC),
		).All(ctx)
	if err != nil {
		return fmt.Errorf("unable to fetch metrics: %w", err)
	}

	// keep track of oldest collection timestamp
	var since *time.Time

	for i, met := range metrics {
		collectedAt := met.CollectedAt
		if since == nil || collectedAt.Before(*since) {
			since = &collectedAt
		}

		bouncerName := met.GeneratedBy

		type bouncerMetrics struct {
			Metrics []models.DetailedMetrics `json:"metrics"`
		}

		payload := bouncerMetrics{}

		err := json.Unmarshal([]byte(met.Payload), &payload)
		if err != nil {
			log.Warningf("while parsing metrics: %s", err)
		}

		fmt.Printf("row %d, %s, %+v\n", i, bouncerName, payload)

		for _, m := range payload.Metrics {
			for _, item := range m.Items {
				labels := item.Labels

				// these are mandatory but we got pointers, so...
				// XXX: but we should only print these once, even for repeated offenses

				if item.Name == nil {
					log.Warningf("missing 'name' field in metrics reported by %s", bouncerName)
					continue
				}
				name := *item.Name

				if item.Unit == nil {
					log.Warningf("missing 'unit' field in metrics reported by %s", bouncerName)
					continue
				}
				unit := *item.Unit

				if item.Value == nil {
					log.Warningf("missing 'value' field in metrics reported by %s", bouncerName)
					continue
				}
				value := *item.Value

				rawMetric := bouncerMetricItem{
					bouncerName: bouncerName,
					ipType:      labels["ip_type"],
					origin:      labels["origin"],
					name:        name,
					unit:        unit,
					value:       value,
				}

				fmt.Printf("raw: %v\n", rawMetric)

				s.rawMetrics = append(s.rawMetrics, rawMetric)
			}
		}
	}

	s.aggregate()

	return nil
}

func (s *statBouncer) aggregate() {
	// [bouncer][origin][name]value
	
	// XXX: how about blocked ips?

	if s.aggregated == nil {
		s.aggregated = make(map[string]map[string]map[string]int64)
	}
	
	for _, raw := range s.rawMetrics {
		if _, ok := s.aggregated[raw.bouncerName]; !ok {
			s.aggregated[raw.bouncerName] = make(map[string]map[string]int64)
		}

		if _, ok := s.aggregated[raw.bouncerName][raw.origin]; !ok {
			s.aggregated[raw.bouncerName][raw.origin] = make(map[string]int64)
		}

		if _, ok := s.aggregated[raw.bouncerName][raw.origin][raw.name]; !ok {
			s.aggregated[raw.bouncerName][raw.origin][raw.name] = 0
		}

		s.aggregated[raw.bouncerName][raw.origin][raw.name] += int64(raw.value)
	}
}

func (s *statBouncer) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	bouncerNames := make(map[string]bool)
	for _, item := range s.rawMetrics {
		bouncerNames[item.bouncerName] = true
	}

	// [bouncer][origin]; where origin=="" is the total

	for bouncerName := range bouncerNames {
		t := cstable.New(out, wantColor)
		t.SetRowLines(false)
		t.SetHeaders("", "Bytes", "Packets")
		t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)
		// XXX: noUnit, showEmpty
		// XXX: total of all origins
		// XXX: blocked_ips and other metrics
		// XXX: -o json

		for origin, metrics := range s.aggregated[bouncerName] {
			t.AddRow(origin,
				strconv.FormatInt(metrics["dropped_bytes"], 10),
				strconv.FormatInt(metrics["dropped_packets"], 10),
			)
		}
		title, _ := s.Description()
		cstable.RenderTitle(out, fmt.Sprintf("\n%s (%s):", title, bouncerName))
		t.Render()
	}

}
