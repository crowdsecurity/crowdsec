package main

import (
	"fmt"
	"io"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func listHubItemTable(out io.Writer, title string, itemType string, itemNames []string) {
	t := newLightTable(out)
	t.SetHeaders("Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	hub, _ := cwhub.GetHub()

	for itemName := range itemNames {
		item := hub.GetItem(itemType, itemNames[itemName])
		status, emo := item.Status()
		t.AddRow(item.Name, fmt.Sprintf("%v  %s", emo, status), item.LocalVersion, item.LocalPath)
	}
	renderTableTitle(out, title)
	t.Render()
}

func scenarioMetricsTable(out io.Writer, itemName string, metrics map[string]int) {
	if metrics["instantiation"] == 0 {
		return
	}
	t := newTable(out)
	t.SetHeaders("Current Count", "Overflows", "Instantiated", "Poured", "Expired")

	t.AddRow(
		fmt.Sprintf("%d", metrics["curr_count"]),
		fmt.Sprintf("%d", metrics["overflow"]),
		fmt.Sprintf("%d", metrics["instantiation"]),
		fmt.Sprintf("%d", metrics["pour"]),
		fmt.Sprintf("%d", metrics["underflow"]),
	)

	renderTableTitle(out, fmt.Sprintf("\n - (Scenario) %s:", itemName))
	t.Render()
}

func parserMetricsTable(out io.Writer, itemName string, metrics map[string]map[string]int) {
	skip := true
	t := newTable(out)
	t.SetHeaders("Parsers", "Hits", "Parsed", "Unparsed")

	for source, stats := range metrics {
		if stats["hits"] > 0 {
			t.AddRow(
				source,
				fmt.Sprintf("%d", stats["hits"]),
				fmt.Sprintf("%d", stats["parsed"]),
				fmt.Sprintf("%d", stats["unparsed"]),
			)
			skip = false
		}
	}

	if !skip {
		renderTableTitle(out, fmt.Sprintf("\n - (Parser) %s:", itemName))
		t.Render()
	}
}
