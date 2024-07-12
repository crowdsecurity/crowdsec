package climetrics

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statLapiBouncer map[string]map[string]map[string]int

func (s statLapiBouncer) Description() (string, string) {
	return "Local API Bouncers Metrics",
		`Tracks total hits to remediation component related API routes.`
}

func (s statLapiBouncer) Process(bouncer, route, method string, val int) {
	if _, ok := s[bouncer]; !ok {
		s[bouncer] = make(map[string]map[string]int)
	}

	if _, ok := s[bouncer][route]; !ok {
		s[bouncer][route] = make(map[string]int)
	}

	s[bouncer][route][method] += val
}

func (s statLapiBouncer) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Route", "Method", "Hits")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	numRows := lapiMetricsToTable(t, s)

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
