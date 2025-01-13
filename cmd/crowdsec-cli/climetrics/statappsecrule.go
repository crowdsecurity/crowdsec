package climetrics

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statAppsecRule map[string]map[string]map[string]int

func (s statAppsecRule) Description() (string, string) {
	return "Appsec Rule Metrics",
		`Provides “per AppSec Component” information about the number of matches for loaded AppSec Rules.`
}

func (s statAppsecRule) Process(appsecEngine, appsecRule string, metric string, val int) {
	if _, ok := s[appsecEngine]; !ok {
		s[appsecEngine] = make(map[string]map[string]int)
	}

	if _, ok := s[appsecEngine][appsecRule]; !ok {
		s[appsecEngine][appsecRule] = make(map[string]int)
	}

	s[appsecEngine][appsecRule][metric] += val
}

func (s statAppsecRule) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	// TODO: sort keys
	for appsecEngine, appsecEngineRulesStats := range s {
		t := cstable.New(out, wantColor).Writer
		t.AppendHeader(table.Row{"Rule ID", "Triggered"})

		keys := []string{"triggered"}

		if numRows, err := metricsToTable(t, appsecEngineRulesStats, keys, noUnit); err != nil {
			log.Warningf("while collecting appsec rules stats: %s", err)
		} else if numRows > 0 || showEmpty {
			t.SetTitle(fmt.Sprintf("Appsec '%s' Rules Metrics", appsecEngine))
			fmt.Fprintln(out, t.Render())
		}
	}
}
