package climetrics

import (
	"fmt"
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

type statDecision map[string]map[string]map[string]int

func (s statDecision) Description() (string, string) {
	return "Local API Decisions",
		`Provides information about all currently active decisions. ` +
			`Includes both local (crowdsec) and global decisions (CAPI), and lists subscriptions (lists).`
}

func (s statDecision) Process(reason, origin, action string, val int) {
	if _, ok := s[reason]; !ok {
		s[reason] = make(map[string]map[string]int)
	}

	if _, ok := s[reason][origin]; !ok {
		s[reason][origin] = make(map[string]int)
	}

	s[reason][origin][action] += val
}

func (s statDecision) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Reason", "Origin", "Action", "Count"})

	numRows := 0

	// TODO: sort by reason, origin, action
	for reason, origins := range s {
		for origin, actions := range origins {
			for action, hits := range actions {
				t.AppendRow(table.Row{
					reason,
					origin,
					action,
					strconv.Itoa(hits),
				})

				numRows++
			}
		}
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		t.SetTitle(title)
		fmt.Fprintln(out, t.Render())
	}
}
