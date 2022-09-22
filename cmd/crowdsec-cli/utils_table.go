package main

import (
	"fmt"
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

func listHubItemTable(out io.Writer, statuses []cwhub.ItemHubStatus) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path"})
	for _, status := range statuses {
		table.Append([]string{status.Name, status.UTF8_Status, status.LocalVersion, status.LocalPath})
	}
	table.Render()
}

func scenarioMetricsTable(out io.Writer, itemName string, metrics map[string]int) {
	if metrics["instanciation"] == 0 {
		return
	}
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Current Count", "Overflows", "Instanciated", "Poured", "Expired"})
	row := []string{
		fmt.Sprintf("%d", metrics["curr_count"]),
		fmt.Sprintf("%d", metrics["overflow"]),
		fmt.Sprintf("%d", metrics["instanciation"]),
		fmt.Sprintf("%d", metrics["pour"]),
		fmt.Sprintf("%d", metrics["underflow"]),
	}
	table.Append(row)

	fmt.Fprintf(out, " - (Scenario) %s: \n", itemName)
	table.Render()
	fmt.Fprintln(out)
}

func parserMetricsTable(out io.Writer, itemName string, metrics map[string]map[string]int) {
	skip := true
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Parsers", "Hits", "Parsed", "Unparsed"})

	for source, stats := range metrics {
		if stats["hits"] > 0 {
			row := []string{
				source,
				fmt.Sprintf("%d", stats["hits"]),
				fmt.Sprintf("%d", stats["parsed"]),
				fmt.Sprintf("%d", stats["unparsed"]),
			}
			table.Append(row)
			skip = false
		}
	}

	if !skip {
		fmt.Fprintf(out, " - (Parser) %s: \n", itemName)
		table.Render()
		fmt.Println()
	}
}
