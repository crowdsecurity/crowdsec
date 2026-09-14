package cliconsole

import (
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// cmdConsoleConnectionTable renders the live link to the console: enrollment, plan and the
// real decision-management state.
func cmdConsoleConnectionTable(out io.Writer, wantColor string, st liveConsoleStatus) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)
	t.SetHeaders("Console connection", "")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft)

	if !st.registered {
		t.AddRow("Central API (CAPI)", emoji.CrossMark+" not registered, see 'cscli capi register'")
		t.Render()

		return
	}

	if !st.reachable {
		t.AddRow("Central API (CAPI)", emoji.CrossMark+" unreachable - showing local options only")
		t.Render()

		return
	}

	t.AddRow("Central API (CAPI)", emoji.CheckMarkButton+" authenticated")

	if !st.capi.Enrolled {
		t.AddRow("Enrolled", emoji.CrossMark+" not enrolled")
		t.Render()
		return
	}

	t.AddRow("Enrolled", emoji.CheckMarkButton+" enrolled")
	t.AddRow("Plan", st.capi.SubscriptionType)

	if st.decisionManagement {
		t.AddRow("Decision management", emoji.CheckMarkButton+" active")
	} else {
		t.AddRow("Decision management", emoji.CrossMark+" inactive (requires SECOPS or ENTERPRISE plan)")
	}

	if st.papi != nil {
		t.AddRow("Last order received", st.papi.LastOrder)
		if len(st.papi.Categories) > 0 {
			t.AddRow("PAPI subscriptions", strings.Join(st.papi.Categories, ", "))
		}
	}

	t.Render()
}

// cmdConsoleStatusTable renders the sharing options.
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
		}

		t.AddRow(option, activated, csconfig.CONSOLE_CONFIGS_HELP[option])
	}

	t.Render()
}
