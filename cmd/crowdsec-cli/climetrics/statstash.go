package climetrics

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statStash map[string]struct {
	Type  string
	Count int
}

func (s statStash) Description() (string, string) {
	return "Parser Stash Metrics",
		`Tracks the status of stashes that might be created by various parsers and scenarios.`
}

func (s statStash) Process(name, mtype string, val int) {
	s[name] = struct {
		Type  string
		Count int
	}{
		Type:  mtype,
		Count: val,
	}
}

func (s statStash) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Name", "Type", "Items"})

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

		t.AppendRow(table.Row{
			alabel,
			astats.Type,
			strconv.Itoa(astats.Count),
		})

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
