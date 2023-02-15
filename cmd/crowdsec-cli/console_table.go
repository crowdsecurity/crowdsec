package main

import (
	"io"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func cmdConsoleStatusTable(out io.Writer, csConfig csconfig.Config) {
	t := newTable(out)
	t.SetRowLines(false)

	t.SetHeaders("Option Name", "Activated", "Description")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, option := range csconfig.CONSOLE_CONFIGS {
		switch option {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios {
				activated = string(emoji.CheckMarkButton)
			}

			t.AddRow(option, activated, "Send alerts from custom scenarios to the console")

		case csconfig.SEND_MANUAL_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions {
				activated = string(emoji.CheckMarkButton)
			}

			t.AddRow(option, activated, "Send manual decisions to the console")

		case csconfig.SEND_TAINTED_SCENARIOS:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios {
				activated = string(emoji.CheckMarkButton)
			}

			t.AddRow(option, activated, "Send alerts from tainted scenarios to the console")
		case csconfig.SEND_CONTEXT:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ShareContext {
				activated = string(emoji.CheckMarkButton)
			}
			t.AddRow(option, activated, "Send context with alerts to the console")
		case csconfig.CONSOLE_MANAGEMENT:
			activated := string(emoji.CrossMark)
			if *csConfig.API.Server.ConsoleConfig.ReceiveDecisions {
				activated = string(emoji.CheckMarkButton)
			}
			t.AddRow(option, activated, "Receive decisions from console")
		}
	}

	t.Render()
}
