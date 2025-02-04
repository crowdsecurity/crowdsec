package climetrics

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statLapiMachine map[string]map[string]map[string]int

func (s statLapiMachine) Description() (string, string) {
	return "Local API Machines Metrics",
		`Tracks the number of calls to the local API from each registered machine.`
}

func (s statLapiMachine) Process(machine, route, method string, val int) {
	if _, ok := s[machine]; !ok {
		s[machine] = make(map[string]map[string]int)
	}

	if _, ok := s[machine][route]; !ok {
		s[machine][route] = make(map[string]int)
	}

	s[machine][route][method] += val
}

func (s statLapiMachine) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Machine", "Route", "Method", "Hits"})

	numRows := lapiMetricsToTable(t, s)

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
