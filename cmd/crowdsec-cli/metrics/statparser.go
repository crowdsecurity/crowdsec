package metrics

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statParser map[string]map[string]int

func (s statParser) Description() (string, string) {
	return "Parser Metrics",
		`Tracks the number of events processed by each parser and indicates success of failure. ` +
			`Zero parsed lines means the parser(s) failed. ` +
			`Non-zero unparsed lines are fine as crowdsec select relevant lines.`
}

func (s statParser) Process(parser, metric string, val int) {
	if _, ok := s[parser]; !ok {
		s[parser] = make(map[string]int)
	}

	s[parser][metric] += val
}

func (s statParser) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Parsers", "Hits", "Parsed", "Unparsed")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	keys := []string{"hits", "parsed", "unparsed"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting parsers stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
