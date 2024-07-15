package climetrics

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statAppsecEngine map[string]map[string]int

func (s statAppsecEngine) Description() (string, string) {
	return "Appsec Metrics",
		`Measures the number of parsed and blocked requests by the AppSec Component.`
}

func (s statAppsecEngine) Process(appsecEngine, metric string, val int) {
	if _, ok := s[appsecEngine]; !ok {
		s[appsecEngine] = make(map[string]int)
	}

	s[appsecEngine][metric] += val
}

func (s statAppsecEngine) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Appsec Engine", "Processed", "Blocked")
	t.SetAlignment(text.AlignLeft, text.AlignLeft)

	keys := []string{"processed", "blocked"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting appsec stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		io.WriteString(out, title + ":\n")
		t.Render()
		io.WriteString(out, "\n")
	}
}
