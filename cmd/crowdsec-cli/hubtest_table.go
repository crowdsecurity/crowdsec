package main

import (
	"fmt"
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/table"
)

func hubTestResultTable(out io.Writer, testResult map[string]bool) {
	t := newLightTable(out)
	t.SetHeaders("Test", "Result")
	t.SetHeaderAlignment(table.AlignLeft)
	t.SetAlignment(table.AlignLeft)

	for testName, success := range testResult {
		status := emoji.CheckMarkButton
		if !success {
			status = emoji.CrossMark
		}

		t.AddRow(testName, status)
	}

	t.Render()
}

func hubTestListTable(out io.Writer, tests []*hubtest.HubTestItem) {
	t := newLightTable(out)
	t.SetHeaders("Name", "Path")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft)

	for _, test := range tests {
		t.AddRow(test.Name, test.Path)
	}

	t.Render()
}

func hubTestParserCoverageTable(out io.Writer, coverage []hubtest.Coverage) {
	t := newLightTable(out)
	t.SetHeaders("Parser", "Status", "Number of tests")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

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

func hubTestAppsecRuleCoverageTable(out io.Writer, coverage []hubtest.Coverage) {
	t := newLightTable(out)
	t.SetHeaders("Appsec Rule", "Status", "Number of tests")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

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

func hubTestScenarioCoverageTable(out io.Writer, coverage []hubtest.Coverage) {
	t := newLightTable(out)
	t.SetHeaders("Scenario", "Status", "Number of tests")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

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
