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
		activated := string(emoji.CrossMark)
		switch option {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_CONTEXT:
			if *csConfig.API.Server.ConsoleConfig.ShareContext {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.CONSOLE_MANAGEMENT:
			if *csConfig.API.Server.ConsoleConfig.ConsoleManagement {
				activated = string(emoji.CheckMarkButton)
			}
		}
		t.AddRow(option, activated, csconfig.CONSOLE_CONFIGS_HELP[option])
	}

	t.Render()
}
