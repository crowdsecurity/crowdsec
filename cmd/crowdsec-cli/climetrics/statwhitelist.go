package climetrics

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statWhitelist map[string]map[string]map[string]int

func (s statWhitelist) Description() (string, string) {
	return "Whitelist Metrics",
		`Tracks the number of events processed and possibly whitelisted by each parser whitelist.`
}

func (s statWhitelist) Process(whitelist, reason, metric string, val int) {
	if _, ok := s[whitelist]; !ok {
		s[whitelist] = make(map[string]map[string]int)
	}

	if _, ok := s[whitelist][reason]; !ok {
		s[whitelist][reason] = make(map[string]int)
	}

	s[whitelist][reason][metric] += val
}

func (s statWhitelist) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Whitelist", "Reason", "Hits", "Whitelisted"})

	if numRows, err := wlMetricsToTable(t, s, noUnit); err != nil {
		log.Warningf("while collecting parsers stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
