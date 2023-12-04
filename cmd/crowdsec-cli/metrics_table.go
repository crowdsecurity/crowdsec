package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/aquasecurity/table"
	log "github.com/sirupsen/logrus"
)

func lapiMetricsToTable(t *table.Table, stats map[string]map[string]map[string]int) int {
	// stats: machine -> route -> method -> count

	// sort keys to keep consistent order when printing
	machineKeys := []string{}
	for k := range stats {
		machineKeys = append(machineKeys, k)
	}
	sort.Strings(machineKeys)

	numRows := 0
	for _, machine := range machineKeys {
		// oneRow: route -> method -> count
		machineRow := stats[machine]
		for routeName, route := range machineRow {
			for methodName, count := range route {
				row := []string{
					machine,
					routeName,
					methodName,
				}
				if count != 0 {
					row = append(row, fmt.Sprintf("%d", count))
				} else {
					row = append(row, "-")
				}
				t.AddRow(row...)
				numRows++
			}
		}
	}
	return numRows
}

func metricsToTable(t *table.Table, stats map[string]map[string]int, keys []string) (int, error) {
	if t == nil {
		return 0, fmt.Errorf("nil table")
	}
	// sort keys to keep consistent order when printing
	sortedKeys := []string{}
	for k := range stats {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	numRows := 0
	for _, alabel := range sortedKeys {
		astats, ok := stats[alabel]
		if !ok {
			continue
		}
		row := []string{
			alabel,
		}
		for _, sl := range keys {
			if v, ok := astats[sl]; ok && v != 0 {
				numberToShow := fmt.Sprintf("%d", v)
				if !noUnit {
					numberToShow = formatNumber(v)
				}

				row = append(row, numberToShow)
			} else {
				row = append(row, "-")
			}
		}
		t.AddRow(row...)
		numRows++
	}
	return numRows, nil
}

func bucketStatsTable(out io.Writer, stats map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bucket", "Current Count", "Overflows", "Instantiated", "Poured", "Expired")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"curr_count", "overflow", "instantiation", "pour", "underflow"}

	if numRows, err := metricsToTable(t, stats, keys); err != nil {
		log.Warningf("while collecting bucket stats: %s", err)
	} else if numRows > 0 {
		renderTableTitle(out, "\nBucket Metrics:")
		t.Render()
	}
}

func acquisStatsTable(out io.Writer, stats map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"reads", "parsed", "unparsed", "pour"}

	if numRows, err := metricsToTable(t, stats, keys); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	} else if numRows > 0 {
		renderTableTitle(out, "\nAcquisition Metrics:")
		t.Render()
	}
}

func appsecMetricsToTable(out io.Writer, metrics map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Appsec Engine", "Processed", "Blocked")
	t.SetAlignment(table.AlignLeft, table.AlignLeft)
	keys := []string{"processed", "blocked"}
	if numRows, err := metricsToTable(t, metrics, keys); err != nil {
		log.Warningf("while collecting appsec stats: %s", err)
	} else if numRows > 0 {
		renderTableTitle(out, "\nAppsec Metrics:")
		t.Render()
	}
}

func appsecRulesToTable(out io.Writer, metrics map[string]map[string]map[string]int) {
	for appsecEngine, appsecEngineRulesStats := range metrics {
		t := newTable(out)
		t.SetRowLines(false)
		t.SetHeaders("Rule ID", "Triggered")
		t.SetAlignment(table.AlignLeft, table.AlignLeft)
		keys := []string{"triggered"}
		if numRows, err := metricsToTable(t, appsecEngineRulesStats, keys); err != nil {
			log.Warningf("while collecting appsec rules stats: %s", err)
		} else if numRows > 0 {
			renderTableTitle(out, fmt.Sprintf("\nAppsec '%s' Rules Metrics:", appsecEngine))
			t.Render()
		}
	}

}

func parserStatsTable(out io.Writer, stats map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Parsers", "Hits", "Parsed", "Unparsed")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"hits", "parsed", "unparsed"}

	if numRows, err := metricsToTable(t, stats, keys); err != nil {
		log.Warningf("while collecting parsers stats: %s", err)
	} else if numRows > 0 {
		renderTableTitle(out, "\nParser Metrics:")
		t.Render()
	}
}

func stashStatsTable(out io.Writer, stats map[string]struct {
	Type  string
	Count int
}) {

	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Name", "Type", "Items")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	sortedKeys := []string{}
	for k := range stats {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	numRows := 0
	for _, alabel := range sortedKeys {
		astats := stats[alabel]

		row := []string{
			alabel,
			astats.Type,
			fmt.Sprintf("%d", astats.Count),
		}
		t.AddRow(row...)
		numRows++
	}
	if numRows > 0 {
		renderTableTitle(out, "\nParser Stash Metrics:")
		t.Render()
	}
}

func lapiStatsTable(out io.Writer, stats map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	sortedKeys := []string{}
	for k := range stats {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	numRows := 0
	for _, alabel := range sortedKeys {
		astats := stats[alabel]

		subKeys := []string{}
		for skey := range astats {
			subKeys = append(subKeys, skey)
		}
		sort.Strings(subKeys)

		for _, sl := range subKeys {
			row := []string{
				alabel,
				sl,
				fmt.Sprintf("%d", astats[sl]),
			}
			t.AddRow(row...)
			numRows++
		}
	}

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Metrics:")
		t.Render()
	}
}

func lapiMachineStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Machine", "Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := lapiMetricsToTable(t, stats)

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Machines Metrics:")
		t.Render()
	}
}

func lapiBouncerStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := lapiMetricsToTable(t, stats)

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Bouncers Metrics:")
		t.Render()
	}
}

func lapiDecisionStatsTable(out io.Writer, stats map[string]struct {
	NonEmpty int
	Empty    int
},
) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Empty answers", "Non-empty answers")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := 0
	for bouncer, hits := range stats {
		t.AddRow(
			bouncer,
			fmt.Sprintf("%d", hits.Empty),
			fmt.Sprintf("%d", hits.NonEmpty),
		)
		numRows++
	}

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Bouncers Decisions:")
		t.Render()
	}
}

func decisionStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Origin", "Action", "Count")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := 0
	for reason, origins := range stats {
		for origin, actions := range origins {
			for action, hits := range actions {
				t.AddRow(
					reason,
					origin,
					action,
					fmt.Sprintf("%d", hits),
				)
				numRows++
			}
		}
	}

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Decisions:")
		t.Render()
	}
}

func alertStatsTable(out io.Writer, stats map[string]int) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Count")
	t.SetAlignment(table.AlignLeft, table.AlignLeft)

	numRows := 0
	for scenario, hits := range stats {
		t.AddRow(
			scenario,
			fmt.Sprintf("%d", hits),
		)
		numRows++
	}

	if numRows > 0 {
		renderTableTitle(out, "\nLocal API Alerts:")
		t.Render()
	}
}
