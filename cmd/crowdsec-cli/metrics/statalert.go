package metrics

import (
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

func (s statAlert) Description() (string, string) {
	return "Local API Alerts",
		`Tracks the total number of past and present alerts for the installed scenarios.`
}

func (s statAlert) Process(reason string, val int) {
	s[reason] += val
}

func (s statAlert) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Count")
	t.SetAlignment(text.AlignLeft, text.AlignLeft)

	numRows := 0

	for scenario, hits := range s {
		t.AddRow(
			scenario,
			strconv.Itoa(hits),
		)

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
