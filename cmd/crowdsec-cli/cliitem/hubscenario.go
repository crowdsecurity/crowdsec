package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewScenario(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.SCENARIOS,
		singular:  "scenario",
		oneOrMore: "scenario(s)",
		help: cliHelp{
			example: `cscli scenarios list -a
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing
`,
		},
		installHelp: cliHelp{
			example: `# Install some scenarios.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run -o raw

# Download only, to be installed later.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing -i
cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some scenarios.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing --purge

# Remove tainted items.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing -i
cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some scenarios. If they are not currently installed, they are downloaded but not installed.
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing -i
cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, metrics and ancestor collections of scenarios (installed or not).
cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing

# Don't collect metrics (avoid error if crowdsec is not running).
cscli scenarios inspect crowdsecurity/ssh-bf --no-metrics

# Display difference between a tainted item and the latest one.
cscli scenarios inspect crowdsecurity/ssh-bf --diff

# Reverse the above diff
cscli scenarios inspect crowdsecurity/ssh-bf --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) scenarios.
cscli scenarios list

# List all available scenarios (installed or not).
cscli scenarios list -a

# List specific scenarios (installed or not).
cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
	}
}
