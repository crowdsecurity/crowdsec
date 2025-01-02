package climetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// bouncerMetricItem represents unaggregated, denormalized metric data.
// Possibly not unique if a bouncer sent the same data multiple times.
type bouncerMetricItem struct {
	collectedAt time.Time
	bouncerName string
	ipType      string
	origin      string
	name        string
	unit        string
	value       float64
}

// aggregationOverTime is the first level of aggregation: we aggregate
// over time, then over ip type, then over origin. we only sum values
// for non-gauge metrics, and take the last value for gauge metrics.
type aggregationOverTime map[string]map[string]map[string]map[string]map[string]int64

func (a aggregationOverTime) add(bouncerName, origin, name, unit, ipType string, value float64, isGauge bool) {
	if _, ok := a[bouncerName]; !ok {
		a[bouncerName] = make(map[string]map[string]map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][origin]; !ok {
		a[bouncerName][origin] = make(map[string]map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][origin][name]; !ok {
		a[bouncerName][origin][name] = make(map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][origin][name][unit]; !ok {
		a[bouncerName][origin][name][unit] = make(map[string]int64)
	}

	if isGauge {
		a[bouncerName][origin][name][unit][ipType] = int64(value)
	} else {
		a[bouncerName][origin][name][unit][ipType] += int64(value)
	}
}

// aggregationOverIPType is the second level of aggregation: data is summed
// regardless of the metrics type (gauge or not). This is used to display
// table rows, they won't differentiate ipv4 and ipv6
type aggregationOverIPType map[string]map[string]map[string]map[string]int64

func (a aggregationOverIPType) add(bouncerName, origin, name, unit string, value int64) {
	if _, ok := a[bouncerName]; !ok {
		a[bouncerName] = make(map[string]map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][origin]; !ok {
		a[bouncerName][origin] = make(map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][origin][name]; !ok {
		a[bouncerName][origin][name] = make(map[string]int64)
	}

	a[bouncerName][origin][name][unit] += value
}

// aggregationOverOrigin is the third level of aggregation: these are
// the totals at the end of the table. Metrics without an origin will
// be added to the totals but not displayed in the rows, only in the footer.
type aggregationOverOrigin map[string]map[string]map[string]int64

func (a aggregationOverOrigin) add(bouncerName, name, unit string, value int64) {
	if _, ok := a[bouncerName]; !ok {
		a[bouncerName] = make(map[string]map[string]int64)
	}

	if _, ok := a[bouncerName][name]; !ok {
		a[bouncerName][name] = make(map[string]int64)
	}

	a[bouncerName][name][unit] += value
}

type statBouncer struct {
	// oldest collection timestamp for each bouncer
	oldestTS map[string]time.Time
	// aggregate over ip type: always sum
	// [bouncer][origin][name][unit]value
	aggOverIPType aggregationOverIPType
	// aggregate over origin: always sum
	// [bouncer][name][unit]value
	aggOverOrigin aggregationOverOrigin
}

var knownPlurals = map[string]string{
	"byte":   "bytes",
	"packet": "packets",
	"ip":     "IPs",
}

func (s *statBouncer) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.aggOverIPType)
}

func (*statBouncer) Description() (string, string) {
	return "Bouncer Metrics",
		`Network traffic blocked by bouncers.`
}

func logWarningOnce(warningsLogged map[string]bool, msg string) {
	if _, ok := warningsLogged[msg]; !ok {
		log.Warning(msg)

		warningsLogged[msg] = true
	}
}

// extractRawMetrics converts metrics from the database to a de-normalized, de-duplicated slice
// it returns the slice and the oldest timestamp for each bouncer
func (*statBouncer) extractRawMetrics(metrics []*ent.Metric) ([]bouncerMetricItem, map[string]time.Time) {
	oldestTS := make(map[string]time.Time)

	// don't spam the user with the same warnings
	warningsLogged := make(map[string]bool)

	// store raw metrics, de-duplicated in case some were sent multiple times
	uniqueRaw := make(map[bouncerMetricItem]struct{})

	for _, met := range metrics {
		bouncerName := met.GeneratedBy

		var payload struct {
			Metrics []models.DetailedMetrics `json:"metrics"`
		}

		if err := json.Unmarshal([]byte(met.Payload), &payload); err != nil {
			log.Warningf("while parsing metrics for %s: %s", bouncerName, err)
			continue
		}

		for _, m := range payload.Metrics {
			// fields like timestamp, name, etc. are mandatory but we got pointers, so we check anyway
			if m.Meta.UtcNowTimestamp == nil {
				logWarningOnce(warningsLogged, "missing 'utc_now_timestamp' field in metrics reported by "+bouncerName)
				continue
			}

			collectedAt := time.Unix(*m.Meta.UtcNowTimestamp, 0).UTC()

			if oldestTS[bouncerName].IsZero() || collectedAt.Before(oldestTS[bouncerName]) {
				oldestTS[bouncerName] = collectedAt
			}

			for _, item := range m.Items {
				valid := true

				if item.Name == nil {
					logWarningOnce(warningsLogged, "missing 'name' field in metrics reported by "+bouncerName)

					// no continue - keep checking the rest
					valid = false
				}

				if item.Unit == nil {
					logWarningOnce(warningsLogged, "missing 'unit' field in metrics reported by "+bouncerName)

					valid = false
				}

				if item.Value == nil {
					logWarningOnce(warningsLogged, "missing 'value' field in metrics reported by "+bouncerName)

					valid = false
				}

				if !valid {
					continue
				}

				rawMetric := bouncerMetricItem{
					collectedAt: collectedAt,
					bouncerName: bouncerName,
					ipType:      item.Labels["ip_type"],
					origin:      item.Labels["origin"],
					name:        *item.Name,
					unit:        *item.Unit,
					value:       *item.Value,
				}

				uniqueRaw[rawMetric] = struct{}{}
			}
		}
	}

	// extract raw metric structs
	keys := make([]bouncerMetricItem, 0, len(uniqueRaw))
	for key := range uniqueRaw {
		keys = append(keys, key)
	}

	// order them by timestamp
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].collectedAt.Before(keys[j].collectedAt)
	})

	return keys, oldestTS
}

func (s *statBouncer) Fetch(ctx context.Context, db *database.Client) error {
	if db == nil {
		return nil
	}

	// query all bouncer metrics that have not been flushed

	metrics, err := db.Ent.Metric.Query().
		Where(metric.GeneratedTypeEQ(metric.GeneratedTypeRC)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("unable to fetch metrics: %w", err)
	}

	// de-normalize, de-duplicate metrics and keep the oldest timestamp for each bouncer

	rawMetrics, oldestTS := s.extractRawMetrics(metrics)

	s.oldestTS = oldestTS
	aggOverTime := s.newAggregationOverTime(rawMetrics)
	s.aggOverIPType = s.newAggregationOverIPType(aggOverTime)
	s.aggOverOrigin = s.newAggregationOverOrigin(s.aggOverIPType)

	return nil
}

// return true if the metric is a gauge and should not be aggregated
func (*statBouncer) isGauge(name string) bool {
	return name == "active_decisions" || strings.HasSuffix(name, "_gauge")
}

// formatMetricName returns the metric name to display in the table header
func (*statBouncer) formatMetricName(name string) string {
	return strings.TrimSuffix(name, "_gauge")
}

// formatMetricOrigin returns the origin to display in the table rows
// (for example, some users don't know what capi is)
func (*statBouncer) formatMetricOrigin(origin string) string {
	switch origin {
	case "CAPI":
		return origin + " (community blocklist)"
	case "cscli":
		return origin + " (manual decisions)"
	case "crowdsec":
		return origin + " (security engine)"
	default:
		return origin
	}
}

func (s *statBouncer) newAggregationOverTime(rawMetrics []bouncerMetricItem) aggregationOverTime {
	ret := aggregationOverTime{}

	for _, raw := range rawMetrics {
		ret.add(raw.bouncerName, raw.origin, raw.name, raw.unit, raw.ipType, raw.value, s.isGauge(raw.name))
	}

	return ret
}

func (*statBouncer) newAggregationOverIPType(aggMetrics aggregationOverTime) aggregationOverIPType {
	ret := aggregationOverIPType{}

	for bouncerName := range aggMetrics {
		for origin := range aggMetrics[bouncerName] {
			for name := range aggMetrics[bouncerName][origin] {
				for unit := range aggMetrics[bouncerName][origin][name] {
					for ipType := range aggMetrics[bouncerName][origin][name][unit] {
						value := aggMetrics[bouncerName][origin][name][unit][ipType]
						ret.add(bouncerName, origin, name, unit, value)
					}
				}
			}
		}
	}

	return ret
}

func (*statBouncer) newAggregationOverOrigin(aggMetrics aggregationOverIPType) aggregationOverOrigin {
	ret := aggregationOverOrigin{}

	for bouncerName := range aggMetrics {
		for origin := range aggMetrics[bouncerName] {
			for name := range aggMetrics[bouncerName][origin] {
				for unit := range aggMetrics[bouncerName][origin][name] {
					val := aggMetrics[bouncerName][origin][name][unit]
					ret.add(bouncerName, name, unit, val)
				}
			}
		}
	}

	return ret
}

// bouncerTable displays a table of metrics for a single bouncer
func (s *statBouncer) bouncerTable(out io.Writer, bouncerName string, wantColor string, noUnit bool) {
	columns := make(map[string]map[string]struct{})

	bouncerData, ok := s.aggOverOrigin[bouncerName]
	if !ok {
		// no metrics for this bouncer, skip. how did we get here ?
		// anyway we can't honor the "showEmpty" flag in this case,
		// we don't even have the table headers
		return
	}

	for metricName, units := range bouncerData {
		// build a map of the metric names and units, to display dynamic columns
		columns[metricName] = make(map[string]struct{})
		for unit := range units {
			columns[metricName][unit] = struct{}{}
		}
	}

	if len(columns) == 0 {
		return
	}

	t := cstable.New(out, wantColor).Writer
	header1 := table.Row{"Origin"}
	header2 := table.Row{""}
	colNum := 1

	colCfg := []table.ColumnConfig{{
		Number:      colNum,
		AlignHeader: text.AlignLeft,
		Align:       text.AlignLeft,
		AlignFooter: text.AlignRight,
	}}

	for _, name := range maptools.SortedKeys(columns) {
		for _, unit := range maptools.SortedKeys(columns[name]) {
			colNum += 1

			header1 = append(header1, s.formatMetricName(name))

			// we don't add "s" to random words
			if plural, ok := knownPlurals[unit]; ok {
				unit = plural
			}

			header2 = append(header2, unit)
			colCfg = append(colCfg, table.ColumnConfig{
				Number:      colNum,
				AlignHeader: text.AlignCenter,
				Align:       text.AlignRight,
				AlignFooter: text.AlignRight,
			})
		}
	}

	t.AppendHeader(header1, table.RowConfig{AutoMerge: true})
	t.AppendHeader(header2)

	t.SetColumnConfigs(colCfg)

	numRows := 0

	// sort all the ranges for stable output

	for _, origin := range maptools.SortedKeys(s.aggOverIPType[bouncerName]) {
		if origin == "" {
			// if the metric has no origin (i.e. processed bytes/packets)
			// we don't display it in the table body but it still gets aggreagted
			// in the footer's totals
			continue
		}

		metrics := s.aggOverIPType[bouncerName][origin]

		row := table.Row{s.formatMetricOrigin(origin)}

		for _, name := range maptools.SortedKeys(columns) {
			for _, unit := range maptools.SortedKeys(columns[name]) {
				valStr := "-"

				if val, ok := metrics[name][unit]; ok {
					valStr = formatNumber(val, !noUnit)
				}

				row = append(row, valStr)
			}
		}

		t.AppendRow(row)

		numRows += 1
	}

	totals := s.aggOverOrigin[bouncerName]

	if numRows == 0 {
		t.Style().Options.SeparateFooter = false
	}

	footer := table.Row{"Total"}

	for _, name := range maptools.SortedKeys(columns) {
		for _, unit := range maptools.SortedKeys(columns[name]) {
			footer = append(footer, formatNumber(totals[name][unit], !noUnit))
		}
	}

	t.AppendFooter(footer)

	title, _ := s.Description()
	title = fmt.Sprintf("%s (%s)", title, bouncerName)

	if s.oldestTS != nil {
		// if you change this to .Local() beware of tests
		title = fmt.Sprintf("%s since %s", title, s.oldestTS[bouncerName].String())
	}

	t.SetTitle(title)
	fmt.Fprintln(out, t.Render())
}

// Table displays a table of metrics for each bouncer
func (s *statBouncer) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	found := false

	for _, bouncerName := range maptools.SortedKeys(s.aggOverOrigin) {
		s.bouncerTable(out, bouncerName, wantColor, noUnit)

		found = true
	}

	if !found && showEmpty {
		fmt.Fprintln(out, "No bouncer metrics found.")
	}
}
