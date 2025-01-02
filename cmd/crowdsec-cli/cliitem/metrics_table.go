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

	t.SetTitle("(AppSec) " + itemName)
	fmt.Fprintln(out, t.Render())
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

	t.SetTitle("(Scenario) " + itemName)
	fmt.Fprintln(out, t.Render())
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
		t.SetTitle("(Parser) " + itemName)
		fmt.Fprintln(out, t.Render())
	}
}
