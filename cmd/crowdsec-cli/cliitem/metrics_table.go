package cliitem

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)


func appsecMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]int) {
	t := cstable.NewLight(out, wantColor).Writer
	t.AppendHeader(table.Row{"Inband Hits", "Outband Hits"})

	t.AppendRow(table.Row{
		strconv.Itoa(metrics["inband_hits"]),
		strconv.Itoa(metrics["outband_hits"]),
	})

	io.WriteString(out, fmt.Sprintf("\n - (AppSec Rule) %s:\n", itemName))
	io.WriteString(out, t.Render()+"\n")
}

func scenarioMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]int) {
	if metrics["instantiation"] == 0 {
		return
	}

	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Current Count", "Overflows", "Instantiated", "Poured", "Expired"})

	t.AppendRow(table.Row{
		strconv.Itoa(metrics["curr_count"]),
		strconv.Itoa(metrics["overflow"]),
		strconv.Itoa(metrics["instantiation"]),
		strconv.Itoa(metrics["pour"]),
		strconv.Itoa(metrics["underflow"]),
	})

	io.WriteString(out, fmt.Sprintf("\n - (Scenario) %s:\n", itemName))
	io.WriteString(out, t.Render()+"\n")
}

func parserMetricsTable(out io.Writer, wantColor string, itemName string, metrics map[string]map[string]int) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Parsers", "Hits", "Parsed", "Unparsed"})

	// don't show table if no hits
	showTable := false

	for source, stats := range metrics {
		if stats["hits"] > 0 {
			t.AppendRow(table.Row{
				source,
				strconv.Itoa(stats["hits"]),
				strconv.Itoa(stats["parsed"]),
				strconv.Itoa(stats["unparsed"]),
			})

			showTable = true
		}
	}

	if showTable {
		io.WriteString(out, fmt.Sprintf("\n - (Parser) %s:\n", itemName))
		io.WriteString(out, t.Render()+"\n")
	}
}
