package climetrics

import (
	"fmt"
	"io"
	"sort"

	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
)

// statAppsecChallenge holds two views of the bot-detection counters:
//
//   - Funnel: per-engine aggregates rendered as one row per appsec_engine,
//     with columns for each lifecycle/outcome bucket. Mirrors the shape
//     statAppsecEngine uses.
//   - Reasons: per-engine per-kind per-reason breakdown so operators can see
//     which RejectSubmission / GrantChallengeCookie strings (and which
//     bounded protocol/cookie reasons) are firing without dropping into
//     Prometheus. Rendered as a second table below the funnel.
type statAppsecChallenge struct {
	Funnel  map[string]map[string]int            `json:"funnel"`
	Reasons map[string]map[string]map[string]int `json:"reasons"` // engine -> kind -> reason -> count
}

func newStatAppsecChallenge() *statAppsecChallenge {
	return &statAppsecChallenge{
		Funnel:  map[string]map[string]int{},
		Reasons: map[string]map[string]map[string]int{},
	}
}

func (*statAppsecChallenge) Description() (string, string) {
	return "Bot Detection Metrics",
		`Measures the challenge lifecycle of the AppSec component.`
}

func (s *statAppsecChallenge) Process(appsecEngine, metric string, val int) {
	if _, ok := s.Funnel[appsecEngine]; !ok {
		s.Funnel[appsecEngine] = make(map[string]int)
	}

	s.Funnel[appsecEngine][metric] += val
}

// ProcessReason records a per-kind/reason datapoint. Empty reasons are
// dropped.
func (s *statAppsecChallenge) ProcessReason(appsecEngine, kind, reason string, val int) {
	if reason == "" {
		return
	}

	if _, ok := s.Reasons[appsecEngine]; !ok {
		s.Reasons[appsecEngine] = map[string]map[string]int{}
	}

	if _, ok := s.Reasons[appsecEngine][kind]; !ok {
		s.Reasons[appsecEngine][kind] = map[string]int{}
	}

	s.Reasons[appsecEngine][kind][reason] += val
}

func (s *statAppsecChallenge) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Bot Detection", "Requested", "Submitted", "Solved", "Granted", "Exempt", "Protocol Failures", "Submissions Rejected", "Cookies Invalid"})

	keys := []string{"requested", "submitted", "solved", "granted", "exempt", "rejected_protocol", "rejected_submission", "rejected_cookie"}

	numRows, err := metricsToTable(t, s.Funnel, keys, noUnit)
	if err != nil {
		log.Warningf("while collecting appsec challenge stats: %s", err)
		return
	}

	if numRows == 0 && !showEmpty {
		return
	}

	title, _ := s.Description()
	t.SetTitle(title)
	fmt.Fprintln(out, t.Render())

	// Detail tables: per-engine breakdown of the user-supplied
	// (GrantChallengeCookie / RejectSubmission) and bounded-vocabulary
	// (protocol / cookie) reasons. One table per outcome (accepted /
	// rejected) so the kind dimension only needs to show up where it
	// actually varies.
	s.renderAccepted(out, wantColor, noUnit)
	s.renderExempted(out, wantColor, noUnit)
	s.renderRejected(out, wantColor, noUnit)
}

// rejectedKindDisplay maps a rejected sub-kind to the label shown in the
// rejected breakdown table.
var rejectedKindDisplay = map[string]string{
	"protocol":   "protocol",
	"submission": "submission",
	"cookie":     "cookie",
}

// rejectedKindOrder fixes the row order so the rendered table is stable
// across runs and groups related kinds together.
var rejectedKindOrder = []string{"protocol", "submission", "cookie"}

// renderAccepted renders the per-engine breakdown of GrantChallengeCookie
// reasons. Only kind="granted" carries a reason (kind="solved" has none by
// design), so the Kind column is dropped here and the table footer carries
// a grand total across all engines and reasons.
func (s *statAppsecChallenge) renderAccepted(out io.Writer, wantColor string, noUnit bool) {
	engines := make([]string, 0, len(s.Reasons))
	for e, byKind := range s.Reasons {
		if _, ok := byKind["granted"]; ok {
			engines = append(engines, e)
		}
	}
	if len(engines) == 0 {
		return
	}
	sort.Strings(engines)

	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Appsec Engine", "Reason", "Count"})

	total := int64(0)
	for _, engine := range engines {
		counts := s.Reasons[engine]["granted"]
		reasons := make([]string, 0, len(counts))
		for r := range counts {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			t.AppendRow(table.Row{engine, r, formatNumber(int64(counts[r]), !noUnit)})
			total += int64(counts[r])
		}
	}

	t.AppendFooter(table.Row{"Total", "", formatNumber(total, !noUnit)})
	t.SetTitle("Bot Detection — Accepted")
	fmt.Fprintln(out, t.Render())
}

// renderExempted renders the per-engine breakdown of ExemptFromChallenge
// reasons (a bot kind like "gptbot" or a path class like "api"). One reason
// per row, footer carries a grand total across engines and reasons.
func (s *statAppsecChallenge) renderExempted(out io.Writer, wantColor string, noUnit bool) {
	engines := make([]string, 0, len(s.Reasons))
	for e, byKind := range s.Reasons {
		if _, ok := byKind["exempt"]; ok {
			engines = append(engines, e)
		}
	}
	if len(engines) == 0 {
		return
	}
	sort.Strings(engines)

	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Appsec Engine", "Reason", "Count"})

	total := int64(0)
	for _, engine := range engines {
		counts := s.Reasons[engine]["exempt"]
		reasons := make([]string, 0, len(counts))
		for r := range counts {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			t.AppendRow(table.Row{engine, r, formatNumber(int64(counts[r]), !noUnit)})
			total += int64(counts[r])
		}
	}

	t.AppendFooter(table.Row{"Total", "", formatNumber(total, !noUnit)})
	t.SetTitle("Bot Detection — Exempted")
	fmt.Fprintln(out, t.Render())
}

// renderRejected renders the per-engine per-kind per-reason breakdown of
// rejected outcomes. Kind matters here (protocol vs submission vs cookie),
// and the table footer carries a grand total across all rows.
func (s *statAppsecChallenge) renderRejected(out io.Writer, wantColor string, noUnit bool) {
	engines := make([]string, 0, len(s.Reasons))
	for e, byKind := range s.Reasons {
		for _, kind := range rejectedKindOrder {
			if _, ok := byKind[kind]; ok {
				engines = append(engines, e)
				break
			}
		}
	}
	if len(engines) == 0 {
		return
	}
	sort.Strings(engines)

	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Appsec Engine", "Kind", "Reason", "Count"})

	total := int64(0)
	for _, engine := range engines {
		byKind := s.Reasons[engine]
		for _, kind := range rejectedKindOrder {
			counts, ok := byKind[kind]
			if !ok {
				continue
			}
			reasons := make([]string, 0, len(counts))
			for r := range counts {
				reasons = append(reasons, r)
			}
			sort.Strings(reasons)
			for _, r := range reasons {
				t.AppendRow(table.Row{engine, rejectedKindDisplay[kind], r, formatNumber(int64(counts[r]), !noUnit)})
				total += int64(counts[r])
			}
		}
	}

	t.AppendFooter(table.Row{"Total", "", "", formatNumber(total, !noUnit)})
	t.SetTitle("Bot Detection — Rejected")
	fmt.Fprintln(out, t.Render())
}
