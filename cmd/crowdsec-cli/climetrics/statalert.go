package climetrics

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statAlert map[string]int

func (s statAlert) Description() (string, string) {
	return "Local API Alerts",
		`Tracks the total number of past and present alerts for the installed scenarios.`
}

func (s statAlert) Process(reason string, val int) {
	s[reason] += val
}

func (s statAlert) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Reason", "Count"})

	numRows := 0

	// TODO: sort keys
	for scenario, hits := range s {
		t.AppendRow(table.Row{
			scenario,
			strconv.Itoa(hits),
		})

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
