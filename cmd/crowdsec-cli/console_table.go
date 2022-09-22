package main

import (
	"io"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

func cmdConsoleStatusTable(out io.Writer, csConfig csconfig.Config) {
	table := tablewriter.NewWriter(out)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Option Name", "Activated", "Description"})

	for _, option := range csconfig.CONSOLE_CONFIGS {
		switch option {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios {
				activated = string(emoji.CheckMarkButton)
			}

			table.Append([]string{option, activated, "Send alerts from custom scenarios to the console"})

		case csconfig.SEND_MANUAL_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions {
				activated = string(emoji.CheckMarkButton)
			}

			table.Append([]string{option, activated, "Send manual decisions to the console"})

		case csconfig.SEND_TAINTED_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios {
				activated = string(emoji.CheckMarkButton)
			}

			table.Append([]string{option, activated, "Send alerts from tainted scenarios to the console"})
		}
	}

	table.Render()
}
