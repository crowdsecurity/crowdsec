package climetrics

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statLapiDecision map[string]struct {
	NonEmpty int
	Empty    int
}

func (s statLapiDecision) Description() (string, string) {
	return "Local API Bouncers Decisions",
		`Tracks the number of empty/non-empty answers from LAPI to bouncers that are working in "live" mode.`
}

func (s statLapiDecision) Process(bouncer, fam string, val int) {
	if _, ok := s[bouncer]; !ok {
		s[bouncer] = struct {
			NonEmpty int
			Empty    int
		}{}
	}

	x := s[bouncer]

	switch fam {
	case "cs_lapi_decisions_ko_total":
		x.Empty += val
	case "cs_lapi_decisions_ok_total":
		x.NonEmpty += val
	}

	s[bouncer] = x
}

func (s statLapiDecision) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Bouncer", "Empty answers", "Non-empty answers"})

	numRows := 0

	for bouncer, hits := range s {
		t.AppendRow(table.Row{
			bouncer,
			strconv.Itoa(hits.Empty),
			strconv.Itoa(hits.NonEmpty),
		})

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
