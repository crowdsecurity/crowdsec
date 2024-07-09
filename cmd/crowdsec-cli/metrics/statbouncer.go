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

func (s *statBouncer) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.aggregated)
}

func (s *statBouncer) Description() (string, string) {
	return "Bouncer Metrics",
		`Network traffic blocked by bouncers.`
}

func warnOnce(warningsLogged map[string]bool, msg string) {
	if _, ok := warningsLogged[msg]; !ok {
		log.Warningf(msg)
		warningsLogged[msg] = true
	}
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

	// don't spam the user with the same warnings
	warningsLogged := make(map[string]bool)

	for _, met := range metrics {
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

		for _, m := range payload.Metrics {
			for _, item := range m.Items {
				labels := item.Labels

				// these are mandatory but we got pointers, so...
				
				valid := true

				if item.Name == nil {
					warnOnce(warningsLogged, "missing 'name' field in metrics reported by "+bouncerName)
					// no continue - keep checking the rest
					valid = false
				}

				if item.Unit == nil {
					warnOnce(warningsLogged, "missing 'unit' field in metrics reported by "+bouncerName)
					valid = false
				}

				if item.Value == nil {
					warnOnce(warningsLogged, "missing 'value' field in metrics reported by "+bouncerName)
					valid = false
				}

				if !valid {
					continue
				}

				name := *item.Name
				unit := *item.Unit
				value := *item.Value

				rawMetric := bouncerMetricItem{
					bouncerName: bouncerName,
					ipType:      labels["ip_type"],
					origin:      labels["origin"],
					name:        name,
					unit:        unit,
					value:       value,
				}

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

	// TODO: describe CAPI, total with all origins
	
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
		// XXX: total of all origins
		// XXX: blocked_ips and other metrics
		
		numRows := 0

		// we print one table per bouncer only if it has stats, so "showEmpty" has no effect
		// unless we want a global table for all bouncers

		for origin, metrics := range s.aggregated[bouncerName] {
			t.AddRow(origin,
				formatNumber(metrics["dropped_bytes"], noUnit),
				strconv.FormatInt(metrics["dropped_packets"], 10),
			)

			numRows += 1
		}

		if numRows > 0 || showEmpty {
			title, _ := s.Description()
			cstable.RenderTitle(out, fmt.Sprintf("\n%s (%s):", title, bouncerName))
			t.Render()
		}
	}

}
