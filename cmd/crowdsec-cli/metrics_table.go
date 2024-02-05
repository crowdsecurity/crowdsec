package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/aquasecurity/table"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"
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

func metricsToTable(t *table.Table, stats map[string]map[string]int, keys []string, noUnit bool) (int, error) {
	if t == nil {
		return 0, fmt.Errorf("nil table")
	}

	numRows := 0

	for _, alabel := range maptools.SortedKeys(stats) {
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

func (s statBucket) Description() (string, string) {
	return "Bucket Metrics", ""
}

func (s statBucket) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bucket", "Current Count", "Overflows", "Instantiated", "Poured", "Expired")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"curr_count", "overflow", "instantiation", "pour", "underflow"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting bucket stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statAcquis) Description() (string, string) {
	return "Acquisition Metrics",
		`Acquisition indicates the number of lines read, parsed, and unparsed for reach datasource. Zero read lines indicate the datasource is misconfigured or not producing logs. Zero parsed lines indicates the parser(s) didn't work for the produced logs. Keep in mind that crowdsec only "picks" relevant lines, so non-zero parsed lines isn't an issue.`

}

func (s statAcquis) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"reads", "parsed", "unparsed", "pour"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statAppsecEngine) Description() (string, string) {
	return "Appsec Metrics", ""
}

func (s statAppsecEngine) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Appsec Engine", "Processed", "Blocked")
	t.SetAlignment(table.AlignLeft, table.AlignLeft)
	keys := []string{"processed", "blocked"}
	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting appsec stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statAppsecRule) Description() (string, string) {
	return "Appsec Rule Metrics", ""
}

func (s statAppsecRule) Table(out io.Writer, noUnit bool, showEmpty bool) {
	for appsecEngine, appsecEngineRulesStats := range s {
		t := newTable(out)
		t.SetRowLines(false)
		t.SetHeaders("Rule ID", "Triggered")
		t.SetAlignment(table.AlignLeft, table.AlignLeft)
		keys := []string{"triggered"}
		if numRows, err := metricsToTable(t, appsecEngineRulesStats, keys, noUnit); err != nil {
			log.Warningf("while collecting appsec rules stats: %s", err)
		} else if numRows > 0 || showEmpty{
			renderTableTitle(out, fmt.Sprintf("\nAppsec '%s' Rules Metrics:", appsecEngine))
			t.Render()
		}
	}

}

func (s statParser) Description() (string, string) {
	return "Parser Metrics", ""
}

func (s statParser) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Parsers", "Hits", "Parsed", "Unparsed")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	keys := []string{"hits", "parsed", "unparsed"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting parsers stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statStash) Description() (string, string) {
	return "Parser Stash Metrics", ""
}

func (s statStash) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Name", "Type", "Items")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

		row := []string{
			alabel,
			astats.Type,
			fmt.Sprintf("%d", astats.Count),
		}
		t.AddRow(row...)
		numRows++
	}
	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statLapi) Description() (string, string) {
	return "Local API Metrics", ""
}

func (s statLapi) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

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

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statLapiMachine) Description() (string, string) {
	return "Local API Machines Metrics", ""
}

func (s statLapiMachine) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Machine", "Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := lapiMetricsToTable(t, s)

	if numRows > 0 || showEmpty{
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statLapiBouncer) Description() (string, string) {
	return "Local API Bouncers Metrics", ""
}

func (s statLapiBouncer) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Route", "Method", "Hits")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := lapiMetricsToTable(t, s)

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statLapiDecision) Description() (string, string) {
	return "Local API Bouncers Decisions", ""
}

func (s statLapiDecision) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Empty answers", "Non-empty answers")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := 0
	for bouncer, hits := range s {
		t.AddRow(
			bouncer,
			fmt.Sprintf("%d", hits.Empty),
			fmt.Sprintf("%d", hits.NonEmpty),
		)
		numRows++
	}

	if numRows > 0 || showEmpty{
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statDecision) Description() (string, string) {
	return "Local API Decisions", ""
}

func (s statDecision) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Origin", "Action", "Count")
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	numRows := 0
	for reason, origins := range s {
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

	if numRows > 0 || showEmpty{
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}

func (s statAlert) Description() (string, string) {
	return "Local API Alerts", ""
}

func (s statAlert) Table(out io.Writer, noUnit bool, showEmpty bool) {
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Count")
	t.SetAlignment(table.AlignLeft, table.AlignLeft)

	numRows := 0
	for scenario, hits := range s {
		t.AddRow(
			scenario,
			fmt.Sprintf("%d", hits),
		)
		numRows++
	}

	if numRows > 0 || showEmpty{
		title, _ := s.Description()
		renderTableTitle(out, "\n" + title + ":")
		t.Render()
	}
}
