package metrics

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

// ErrNilTable means a nil pointer was passed instead of a table instance. This is a programming error.
var ErrNilTable = errors.New("nil table")

func lapiMetricsToTable(t *cstable.Table, stats map[string]map[string]map[string]int) int {
	// stats: machine -> route -> method -> count
	// sort keys to keep consistent order when printing
	machineKeys := []string{}
	for k := range stats {
		machineKeys = append(machineKeys, k)
	}

	sort.Strings(machineKeys)

	numRows := 0

	for _, machine := range machineKeys {
		// oneRow: route -> method -> count
		machineRow := stats[machine]
		for routeName, route := range machineRow {
			for methodName, count := range route {
				row := []string{
					machine,
					routeName,
					methodName,
				}
				if count != 0 {
					row = append(row, strconv.Itoa(count))
				} else {
					row = append(row, "-")
				}

				t.AddRow(row...)

				numRows++
			}
		}
	}

	return numRows
}

func wlMetricsToTable(t *cstable.Table, stats map[string]map[string]map[string]int, noUnit bool) (int, error) {
	if t == nil {
		return 0, ErrNilTable
	}

	numRows := 0

	for _, name := range maptools.SortedKeys(stats) {
		for _, reason := range maptools.SortedKeys(stats[name]) {
			row := []string{
				name,
				reason,
				"-",
				"-",
			}

			for _, action := range maptools.SortedKeys(stats[name][reason]) {
				value := stats[name][reason][action]

				switch action {
				case "whitelisted":
					row[3] = strconv.Itoa(value)
				case "hits":
					row[2] = strconv.Itoa(value)
				default:
					log.Debugf("unexpected counter '%s' for whitelists = %d", action, value)
				}
			}

			t.AddRow(row...)

			numRows++
		}
	}

	return numRows, nil
}

func metricsToTable(t *cstable.Table, stats map[string]map[string]int, keys []string, noUnit bool) (int, error) {
	if t == nil {
		return 0, ErrNilTable
	}

	numRows := 0

	for _, alabel := range maptools.SortedKeys(stats) {
		astats, ok := stats[alabel]
		if !ok {
			continue
		}

		row := []string{
			alabel,
		}

		for _, sl := range keys {
			if v, ok := astats[sl]; ok && v != 0 {
				numberToShow := strconv.Itoa(v)
				if !noUnit {
					numberToShow = formatNumber(v)
				}

				row = append(row, numberToShow)
			} else {
				row = append(row, "-")
			}
		}

		t.AddRow(row...)

		numRows++
	}

	return numRows, nil
}

func (s statBucket) Description() (string, string) {
	return "Scenario Metrics",
		`Measure events in different scenarios. Current count is the number of buckets during metrics collection. ` +
			`Overflows are past event-producing buckets, while Expired are the ones that didn’t receive enough events to Overflow.`
}

func (s statBucket) Process(bucket, metric string, val int) {
	if _, ok := s[bucket]; !ok {
		s[bucket] = make(map[string]int)
	}

	s[bucket][metric] += val
}

func (s statBucket) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Scenario", "Current Count", "Overflows", "Instantiated", "Poured", "Expired")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	keys := []string{"curr_count", "overflow", "instantiation", "pour", "underflow"}

	if numRows, err := metricsToTable(t, s, keys, noUnit); err != nil {
		log.Warningf("while collecting scenario stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

func (s statAcquis) Description() (string, string) {
	return "Acquisition Metrics",
		`Measures the lines read, parsed, and unparsed per datasource. ` +
			`Zero read lines indicate a misconfigured or inactive datasource. ` +
			`Zero parsed lines mean the parser(s) failed. ` +
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
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

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
	for appsecEngine, appsecEngineRulesStats := range s {
		t := cstable.New(out, wantColor)
		t.SetRowLines(false)
		t.SetHeaders("Rule ID", "Triggered")
		t.SetAlignment(text.AlignLeft, text.AlignLeft)

		keys := []string{"triggered"}

		if numRows, err := metricsToTable(t, appsecEngineRulesStats, keys, noUnit); err != nil {
			log.Warningf("while collecting appsec rules stats: %s", err)
		} else if numRows > 0 || showEmpty {
			cstable.RenderTitle(out, fmt.Sprintf("\nAppsec '%s' Rules Metrics:", appsecEngine))
			t.Render()
		}
	}
}

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
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Whitelist", "Reason", "Hits", "Whitelisted")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	if numRows, err := wlMetricsToTable(t, s, noUnit); err != nil {
		log.Warningf("while collecting parsers stats: %s", err)
	} else if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

func (s statParser) Description() (string, string) {
	return "Parser Metrics",
		`Tracks the number of events processed by each parser and indicates success of failure. ` +
			`Zero parsed lines means the parer(s) failed. ` +
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

func (s statStash) Description() (string, string) {
	return "Parser Stash Metrics",
		`Tracks the status of stashes that might be created by various parsers and scenarios.`
}

func (s statStash) Process(name, mtype string, val int) {
	s[name] = struct {
		Type  string
		Count int
	}{
		Type:  mtype,
		Count: val,
	}
}

func (s statStash) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Name", "Type", "Items")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

		row := []string{
			alabel,
			astats.Type,
			strconv.Itoa(astats.Count),
		}
		t.AddRow(row...)

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

func (s statLapi) Description() (string, string) {
	return "Local API Metrics",
		`Monitors the requests made to local API routes.`
}

func (s statLapi) Process(route, method string, val int) {
	if _, ok := s[route]; !ok {
		s[route] = make(map[string]int)
	}

	s[route][method] += val
}

func (s statLapi) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Route", "Method", "Hits")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	// unfortunately, we can't reuse metricsToTable as the structure is too different :/
	numRows := 0

	for _, alabel := range maptools.SortedKeys(s) {
		astats := s[alabel]

		subKeys := []string{}
		for skey := range astats {
			subKeys = append(subKeys, skey)
		}

		sort.Strings(subKeys)

		for _, sl := range subKeys {
			row := []string{
				alabel,
				sl,
				strconv.Itoa(astats[sl]),
			}

			t.AddRow(row...)

			numRows++
		}
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

func (s statLapiMachine) Description() (string, string) {
	return "Local API Machines Metrics",
		`Tracks the number of calls to the local API from each registered machine.`
}

func (s statLapiMachine) Process(machine, route, method string, val int) {
	if _, ok := s[machine]; !ok {
		s[machine] = make(map[string]map[string]int)
	}

	if _, ok := s[machine][route]; !ok {
		s[machine][route] = make(map[string]int)
	}

	s[machine][route][method] += val
}

func (s statLapiMachine) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Machine", "Route", "Method", "Hits")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft, text.AlignLeft)

	numRows := lapiMetricsToTable(t, s)

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

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

func (s statLapiDecision) Description() (string, string) {
	return "Local API Bouncers Decisions",
		`Tracks the number of empty/non-empty answers from LAPI to bouncers that are working in "live" mode.`
}

func (s statLapiDecision) Process(bouncer, fam string, val int) {
	if _, ok := s[bouncer]; !ok {
		s[bouncer] = struct {
			NonEmpty int
			Empty    int
		}{}
	}

	x := s[bouncer]

	switch fam {
	case "cs_lapi_decisions_ko_total":
		x.Empty += val
	case "cs_lapi_decisions_ok_total":
		x.NonEmpty += val
	}

	s[bouncer] = x
}

func (s statLapiDecision) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Bouncer", "Empty answers", "Non-empty answers")
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	numRows := 0

	for bouncer, hits := range s {
		t.AddRow(
			bouncer,
			strconv.Itoa(hits.Empty),
			strconv.Itoa(hits.NonEmpty),
		)

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

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
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}

func (s statAlert) Description() (string, string) {
	return "Local API Alerts",
		`Tracks the total number of past and present alerts for the installed scenarios.`
}

func (s statAlert) Process(reason string, val int) {
	s[reason] += val
}

func (s statAlert) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Reason", "Count")
	t.SetAlignment(text.AlignLeft, text.AlignLeft)

	numRows := 0

	for scenario, hits := range s {
		t.AddRow(
			scenario,
			strconv.Itoa(hits),
		)

		numRows++
	}

	if numRows > 0 || showEmpty {
		title, _ := s.Description()
		cstable.RenderTitle(out, "\n"+title+":")
		t.Render()
	}
}
