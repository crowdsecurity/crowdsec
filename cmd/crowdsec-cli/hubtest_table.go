package main

import (
	"fmt"
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

func hubTestResultTable(out io.Writer, testResult map[string]bool) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Test", "Result"})

	for testName, success := range testResult {
		status := emoji.CheckMarkButton.String()
		if !success {
			status = emoji.CrossMark.String()
		}

		table.Append([]string{testName, status})
	}

	table.Render()
}

func hubTestListTable(out io.Writer, tests []*cstest.HubTestItem) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Name", "Path"})

	for _, test := range tests {
		table.Append([]string{test.Name, test.Path})
	}

	table.Render()
}

func hubTestParserCoverageTable(out io.Writer, coverage []cstest.ParserCoverage) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Parser", "Status", "Number of tests"})

	parserTested := 0
	for _, test := range coverage {
		status := emoji.RedCircle.String()
		if test.TestsCount > 0 {
			status = emoji.GreenCircle.String()
			parserTested++
		}
		table.Append([]string{test.Parser, status, fmt.Sprintf("%d times (across %d tests)", test.TestsCount, len(test.PresentIn))})
	}

	table.Render()
}

func hubTestScenarioCoverageTable(out io.Writer, coverage []cstest.ScenarioCoverage) {
	table := tablewriter.NewWriter(out)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Scenario", "Status", "Number of tests"})

	parserTested := 0
	for _, test := range coverage {
		status := emoji.RedCircle.String()
		if test.TestsCount > 0 {
			status = emoji.GreenCircle.String()
			parserTested++
		}
		table.Append([]string{test.Scenario, status, fmt.Sprintf("%d times (across %d tests)", test.TestsCount, len(test.PresentIn))})
	}

	table.Render()
}
