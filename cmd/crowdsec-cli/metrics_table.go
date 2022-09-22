package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

func lapiMetricsToTable(table *tablewriter.Table, stats map[string]map[string]map[string]int) {
	//stats: machine -> route -> method -> count

	// sort keys to keep consistent order when printing
	machineKeys := []string{}
	for k := range stats {
		machineKeys = append(machineKeys, k)
	}
	sort.Strings(machineKeys)

	for _, machine := range machineKeys {
		// oneRow: route -> method -> count
		machineRow := stats[machine]
		for routeName, route := range machineRow {
			for methodName, count := range route {
				row := []string{}
				row = append(row, machine)
				row = append(row, routeName)
				row = append(row, methodName)
				if count != 0 {
					row = append(row, fmt.Sprintf("%d", count))
				} else {
					row = append(row, "-")
				}
				table.Append(row)
			}
		}
	}
}

func metricsToTable(table *tablewriter.Table, stats map[string]map[string]int, keys []string) error {
	if table == nil {
		return fmt.Errorf("nil table")
	}

	// sort keys to keep consistent order when printing
	sortedKeys := []string{}
	for k := range stats {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, alabel := range sortedKeys {
		astats, ok := stats[alabel]
		if !ok {
			continue
		}
		row := []string{}
		row = append(row, alabel) // name
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
		table.Append(row)
	}
	return nil
}

func maybeRenderMetricTable(out io.Writer, title string, table *tablewriter.Table) {
	if table.NumLines() > 0 {
		fmt.Fprintf(out, "%s:\n", title)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.Render()
	}
}

func bucketStatsTable(out io.Writer, stats map[string]map[string]int) {
	title := "Buckets Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Bucket", "Current Count", "Overflows", "Instantiated", "Poured", "Expired"})
	keys := []string{"curr_count", "overflow", "instanciation", "pour", "underflow"}

	if err := metricsToTable(table, stats, keys); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	}

	maybeRenderMetricTable(out, title, table)
}

func acquisStatsTable(out io.Writer, stats map[string]map[string]int) {
	title := "Acquisition Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket"})
	keys := []string{"reads", "parsed", "unparsed", "pour"}

	if err := metricsToTable(table, stats, keys); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	}

	maybeRenderMetricTable(out, title, table)
}

func parserStatsTable(out io.Writer, stats map[string]map[string]int) {
	title := "Parser Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Parsers", "Hits", "Parsed", "Unparsed"})
	keys := []string{"hits", "parsed", "unparsed"}

	if err := metricsToTable(table, stats, keys); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	}

	maybeRenderMetricTable(out, title, table)
}

func lapiStatsTable(out io.Writer, stats map[string]map[string]int) {
	title := "Local Api Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Route", "Method", "Hits"})

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	sortedKeys := []string{}
	for k := range stats {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

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
			table.Append(row)
		}
	}

	maybeRenderMetricTable(out, title, table)
}

func lapiMachineStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	title := "Local Api Machines Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Machine", "Route", "Method", "Hits"})

	lapiMetricsToTable(table, stats)

	maybeRenderMetricTable(out, title, table)
}

func lapiBouncerStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	title := "Local Api Bouncer Metrics"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Bouncer", "Route", "Method", "Hits"})

	lapiMetricsToTable(table, stats)

	maybeRenderMetricTable(out, title, table)
}

func lapiDecisionStatsTable(out io.Writer, stats map[string]struct{NonEmpty int; Empty int}) {
	title := "Local Api Bouncer Decisions"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Bouncer", "Empty answers", "Non-empty answers"})

	for bouncer, hits := range stats {
		row := []string{
			bouncer,
			fmt.Sprintf("%d", hits.Empty),
			fmt.Sprintf("%d", hits.NonEmpty),
		}
		table.Append(row)
	}

	maybeRenderMetricTable(out, title, table)
}

func decisionStatsTable(out io.Writer, stats map[string]map[string]map[string]int) {
	title := "Local Api Decisions"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Reason", "Origin", "Action", "Count"})

	for reason, origins := range stats {
		for origin, actions := range origins {
			for action, hits := range actions {
				row := []string{
					reason,
					origin,
					action,
					fmt.Sprintf("%d", hits),
				}
				table.Append(row)
			}
		}
	}

	maybeRenderMetricTable(out, title, table)
}

func alertStatsTable(out io.Writer, stats map[string]int) {
	title := "Local Api Alerts"
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Reason", "Count"})

	for scenario, hits := range stats {
		row := []string{
			scenario,
			fmt.Sprintf("%d", hits),
		}
		table.Append(row)
	}

	maybeRenderMetricTable(out, title, table)
}
