package clihubtest

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func hubTestResultTable(out io.Writer, wantColor string, testResult map[string]bool) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders("Test", "Result")
	t.SetHeaderAlignment(text.AlignLeft)
	t.SetAlignment(text.AlignLeft)

	for testName, success := range testResult {
		status := emoji.CheckMarkButton
		if !success {
			status = emoji.CrossMark
		}

		t.AddRow(testName, status)
	}

	t.Render()
}

func hubTestListTable(out io.Writer, wantColor string, tests []*hubtest.HubTestItem) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders("Name", "Path")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft)
	t.SetAlignment(text.AlignLeft, text.AlignLeft)

	for _, test := range tests {
		t.AddRow(test.Name, test.Path)
	}

	t.Render()
}

func hubTestCoverageTable(out io.Writer, wantColor string, headers []string, coverage []hubtest.Coverage) {
	t := cstable.NewLight(out, wantColor)
	t.SetHeaders(headers...)
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)
	t.SetAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	parserTested := 0

	for _, test := range coverage {
		status := emoji.RedCircle
		if test.TestsCount > 0 {
			status = emoji.GreenCircle
			parserTested++
		}

		t.AddRow(test.Name, status, fmt.Sprintf("%d times (across %d tests)", test.TestsCount, len(test.PresentIn)))
	}

	t.Render()
}
