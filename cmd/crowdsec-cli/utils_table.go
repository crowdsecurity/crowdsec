package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func listHubItemTable(hub *cwhub.Hub, out io.Writer, title string, itemType string, items []*cwhub.Item) {
	t := newLightTable(out)
	t.SetHeaders("Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, item := range items {
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
		strconv.Itoa(metrics["curr_count"]),
		strconv.Itoa(metrics["overflow"]),
		strconv.Itoa(metrics["instantiation"]),
		strconv.Itoa(metrics["pour"]),
		strconv.Itoa(metrics["underflow"]),
	)

	renderTableTitle(out, fmt.Sprintf("\n - (Scenario) %s:", itemName))
	t.Render()
}

func parserMetricsTable(out io.Writer, itemName string, metrics map[string]map[string]int) {
	t := newTable(out)
	t.SetHeaders("Parsers", "Hits", "Parsed", "Unparsed")

	// don't show table if no hits
	showTable := false

	for source, stats := range metrics {
		if stats["hits"] > 0 {
			t.AddRow(
				source,
				strconv.Itoa(stats["hits"]),
				strconv.Itoa(stats["parsed"]),
				strconv.Itoa(stats["unparsed"]),
			)
			showTable = true
		}
	}

	if showTable {
		renderTableTitle(out, fmt.Sprintf("\n - (Parser) %s:", itemName))
		t.Render()
	}
}
