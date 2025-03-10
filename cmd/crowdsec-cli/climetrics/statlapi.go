package climetrics

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statLapi map[string]map[string]int

func (s statLapi) Description() (string, string) {
	return "Local API Metrics",
		`Monitors the requests made to local API routes.`
}

func (s statLapi) Process(route, method string, val int) {
	if _, ok := s[route]; !ok {
		s[route] = make(map[string]int)
	}

	s[route][method] += val
}

func (s statLapi) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Route", "Method", "Hits"})

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

		for _, sl := range maptools.SortedKeys(astats) {
			t.AppendRow(table.Row{
				alabel,
				sl,
				strconv.Itoa(astats[sl]),
			})

			numRows++
		}
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
