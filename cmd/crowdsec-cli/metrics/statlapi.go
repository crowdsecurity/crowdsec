package metrics

import (
	"io"
	"sort"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

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
