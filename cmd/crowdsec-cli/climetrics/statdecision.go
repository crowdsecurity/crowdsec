package climetrics

import (
	"io"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"

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
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Origin", "Action", "Count")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	numRows := 0

	for reason, origins := range s {
		for origin, actions := range origins {
			for action, hits := range actions {
				t.AddRow(
					reason,
					origin,
					action,
					strconv.Itoa(hits),
				)

				numRows++
			}
		}
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		io.WriteString(out, title + ":\n")
		t.Render()
		io.WriteString(out, "\n")
	}
}
