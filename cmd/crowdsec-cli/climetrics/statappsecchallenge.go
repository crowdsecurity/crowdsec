package climetrics

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
)

type statAppsecChallenge map[string]map[string]int

func (statAppsecChallenge) Description() (string, string) {
	return "Bot Detection Metrics",
		`Measures the challenge lifecycle of the AppSec component.`
}

func (s statAppsecChallenge) Process(appsecEngine, metric string, val int) {
	if _, ok := s[appsecEngine]; !ok {
		s[appsecEngine] = make(map[string]int)
	}

	s[appsecEngine][metric] += val
}

func (s statAppsecChallenge) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Bot Detection", "Requested", "Submitted", "Solved", "Granted", "Protocol Failures", "Submissions Rejected", "Cookies Invalid"})

	keys := []string{"requested", "submitted", "solved", "granted", "rejected_protocol", "rejected_submission", "rejected_cookie"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting appsec challenge stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
