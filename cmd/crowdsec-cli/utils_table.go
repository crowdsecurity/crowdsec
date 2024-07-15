package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func listHubItemTable(out io.Writer, wantColor string, title string, items []*cwhub.Item) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders("Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	for _, item := range items {
		status := fmt.Sprintf("%v  %s", item.State.Emoji(), item.State.Text())
		t.AddRow(item.Name, status, item.State.LocalVersion, item.State.LocalPath)
	}

	io.WriteString(out, title+"\n")
	t.Render()
}

func appsecMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]int) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders("Inband Hits", "Outband Hits")

	t.AddRow(
		strconv.Itoa(metrics["inband_hits"]),
		strconv.Itoa(metrics["outband_hits"]),
	)

	io.WriteString(out, fmt.Sprintf("\n - (AppSec Rule) %s:\n", itemName))
	t.Render()
}

func scenarioMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]int) {
	if metrics["instantiation"] == 0 {
		return
	}

	t := cstable.New(out, wantColor)
	t.SetHeaders("Current Count", "Overflows", "Instantiated", "Poured", "Expired")

	t.AddRow(
		strconv.Itoa(metrics["curr_count"]),
		strconv.Itoa(metrics["overflow"]),
		strconv.Itoa(metrics["instantiation"]),
		strconv.Itoa(metrics["pour"]),
		strconv.Itoa(metrics["underflow"]),
	)

	io.WriteString(out, fmt.Sprintf("\n - (Scenario) %s:\n", itemName))
	t.Render()
}

func parserMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]map[string]int) {
	t := cstable.New(out, wantColor)
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
		io.WriteString(out, fmt.Sprintf("\n - (Parser) %s:\n", itemName))
		t.Render()
	}
}
