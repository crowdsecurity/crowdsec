package metrics

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statAcquis map[string]map[string]int

func (s statAcquis) Description() (string, string) {
	return "Acquisition Metrics",
		`Measures the lines read, parsed, and unparsed per datasource. ` +
			`Zero read lines indicate a misconfigured or inactive datasource. ` +
			`Zero parsed lines means the parser(s) failed. ` +
			`Non-zero parsed lines are fine as crowdsec selects relevant lines.`
}

func (s statAcquis) Process(source, metric string, val int) {
	if _, ok := s[source]; !ok {
		s[source] = make(map[string]int)
	}

	s[source][metric] += val
}

func (s statAcquis) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Source", "Lines read", "Lines parsed", "Lines unparsed", "Lines poured to bucket", "Lines whitelisted")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	keys := []string{"reads", "parsed", "unparsed", "pour", "whitelisted"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting acquis stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
