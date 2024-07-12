package climetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

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
	aggregated map[string]map[string]map[string]map[string]int64
	aggregatedAllOrigin map[string]map[string]map[string]int64
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
	// [bouncer][origin][name][unit]value
	if s.aggregated == nil {
		s.aggregated = make(map[string]map[string]map[string]map[string]int64)
	}

	if s.aggregatedAllOrigin == nil {
		s.aggregatedAllOrigin = make(map[string]map[string]map[string]int64)
	}

	for _, raw := range s.rawMetrics {
		if _, ok := s.aggregated[raw.bouncerName]; !ok {
			s.aggregated[raw.bouncerName] = make(map[string]map[string]map[string]int64)
		}

		if _, ok := s.aggregated[raw.bouncerName][raw.origin]; !ok {
			s.aggregated[raw.bouncerName][raw.origin] = make(map[string]map[string]int64)
		}

		if _, ok := s.aggregated[raw.bouncerName][raw.origin][raw.name]; !ok {
			s.aggregated[raw.bouncerName][raw.origin][raw.name] = make(map[string]int64)
		}

		if _, ok := s.aggregated[raw.bouncerName][raw.origin][raw.name][raw.unit]; !ok {
			s.aggregated[raw.bouncerName][raw.origin][raw.name][raw.unit] = 0
		}

		s.aggregated[raw.bouncerName][raw.origin][raw.name][raw.unit] += int64(raw.value)

		if _, ok := s.aggregatedAllOrigin[raw.bouncerName]; !ok {
			s.aggregatedAllOrigin[raw.bouncerName] = make(map[string]map[string]int64)
		}

		if _, ok := s.aggregatedAllOrigin[raw.bouncerName][raw.name]; !ok {
			s.aggregatedAllOrigin[raw.bouncerName][raw.name] = make(map[string]int64)
		}

		if _, ok := s.aggregatedAllOrigin[raw.bouncerName][raw.name][raw.unit]; !ok {
			s.aggregatedAllOrigin[raw.bouncerName][raw.name][raw.unit] = 0
		}

		s.aggregatedAllOrigin[raw.bouncerName][raw.name][raw.unit] += int64(raw.value)
	}
}

// bouncerTable displays a table of metrics for a single bouncer
func (s *statBouncer) bouncerTable(out io.Writer, bouncerName string, wantColor string, noUnit bool) {
	columns := make(map[string]map[string]bool)
	for _, item := range s.rawMetrics {
		if item.bouncerName != bouncerName {
			continue
		}
		// build a map of the metric names and units, to display dynamic columns
		if _, ok := columns[item.name]; !ok {
			columns[item.name] = make(map[string]bool)
		}
		columns[item.name][item.unit] = true
	}

	// no metrics for this bouncer, skip. how did we get here ?
	// anyway we can't honor the "showEmpty" flag in this case,
	// we don't heven have the table headers

	if len(columns) == 0 {
		return
	}

	t := cstable.New(out, wantColor).Writer
	header1 := table.Row{"Origin"}
	header2 := table.Row{""}
	colNum := 1

	colCfg := []table.ColumnConfig{{
		Number:colNum,
		AlignHeader:
		text.AlignLeft,
		Align: text.AlignLeft,
		AlignFooter: text.AlignRight,
	}}

	for _, name := range maptools.SortedKeys(columns) {
		for _, unit := range maptools.SortedKeys(columns[name]) {
			colNum += 1
			header1 = append(header1, name)
			header2 = append(header2, unit)
			colCfg = append(colCfg, table.ColumnConfig{
				Number: colNum,
				AlignHeader: text.AlignCenter,
				Align: text.AlignRight,
				AlignFooter: text.AlignRight},
			)
		}
	}

	t.AppendHeader(header1, table.RowConfig{AutoMerge: true})
	t.AppendHeader(header2)

	t.SetColumnConfigs(colCfg)

	numRows := 0

	// sort all the ranges for stable output

	for _, origin := range maptools.SortedKeys(s.aggregated[bouncerName]) {
		metrics := s.aggregated[bouncerName][origin]
		row := table.Row{origin}
		for _, name := range maptools.SortedKeys(columns) {
			for _, unit := range maptools.SortedKeys(columns[name]) {
				row = append(row, formatNumber(metrics[name][unit], !noUnit))
			}
		}
		t.AppendRow(row)

		numRows += 1
	}

	totals := s.aggregatedAllOrigin[bouncerName]

	footer := table.Row{"Total"}
	for _, name := range maptools.SortedKeys(columns) {
		for _, unit := range maptools.SortedKeys(columns[name]) {
			footer = append(footer, formatNumber(totals[name][unit], !noUnit))
		}
	}

	t.AppendFooter(footer)

	if numRows == 0 {
		// this happens only if we decide to discard some data in the loop
		return
	}

	title, _ := s.Description()
	// don't use SetTitle() because it draws the title inside table box
	// TODO: newline position wrt other stat tables
	cstable.RenderTitle(out, fmt.Sprintf("%s (%s):", title, bouncerName))
	fmt.Fprintln(out, t.Render())
}

// Table displays a table of metrics for each bouncer
func (s *statBouncer) Table(out io.Writer, wantColor string, noUnit bool, _ bool) {
	bouncerNames := make(map[string]bool)
	for _, item := range s.rawMetrics {
		bouncerNames[item.bouncerName] = true
	}

	nl := false
	for _, bouncerName := range maptools.SortedKeys(bouncerNames) {
		if nl {
			// empty line between tables
			fmt.Fprintln(out)
		}
		s.bouncerTable(out, bouncerName, wantColor, noUnit)
		nl = true
	}
}
