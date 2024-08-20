package cliconsole

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func cmdConsoleStatusTable(out io.Writer, wantColor string, consoleCfg csconfig.ConsoleConfig) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)

	t.SetHeaders("Option Name", "Activated", "Description")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	for _, option := range csconfig.CONSOLE_CONFIGS {
		activated := emoji.CrossMark

		switch option {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			if *consoleCfg.ShareCustomScenarios {
				activated = emoji.CheckMarkButton
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			if *consoleCfg.ShareManualDecisions {
				activated = emoji.CheckMarkButton
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			if *consoleCfg.ShareTaintedScenarios {
				activated = emoji.CheckMarkButton
			}
		case csconfig.SEND_CONTEXT:
			if *consoleCfg.ShareContext {
				activated = emoji.CheckMarkButton
			}
		case csconfig.CONSOLE_MANAGEMENT:
			if *consoleCfg.ConsoleManagement {
				activated = emoji.CheckMarkButton
			}
		}

		t.AddRow(option, activated, csconfig.CONSOLE_CONFIGS_HELP[option])
	}

	t.Render()
}
