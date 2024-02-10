package main

import (
	"io"

	"github.com/aquasecurity/table"
	"github.com/enescakir/emoji"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func cmdConsoleStatusTable(out io.Writer, consoleCfg csconfig.ConsoleConfig) {
	t := newTable(out)
	t.SetRowLines(false)

	t.SetHeaders("Option Name", "Activated", "Description")
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)

	for _, option := range csconfig.CONSOLE_CONFIGS {
		activated := string(emoji.CrossMark)
		switch option {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			if *consoleCfg.ShareCustomScenarios {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			if *consoleCfg.ShareManualDecisions {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			if *consoleCfg.ShareTaintedScenarios {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.SEND_CONTEXT:
			if *consoleCfg.ShareContext {
				activated = string(emoji.CheckMarkButton)
			}
		case csconfig.CONSOLE_MANAGEMENT:
			if *consoleCfg.ConsoleManagement {
				activated = string(emoji.CheckMarkButton)
			}
		}
		t.AddRow(option, activated, csconfig.CONSOLE_CONFIGS_HELP[option])
	}

	t.Render()
}
