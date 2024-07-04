package metrics

import (
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

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
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Empty answers", "Non-empty answers")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	numRows := 0

	for bouncer, hits := range s {
		t.AddRow(
			bouncer,
			strconv.Itoa(hits.Empty),
			strconv.Itoa(hits.NonEmpty),
		)

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
