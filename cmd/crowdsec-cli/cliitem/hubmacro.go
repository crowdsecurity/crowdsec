package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewMacro(cfg csconfig.Getter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.MACROS,
		singular:  "macro",
		oneOrMore: "macro(s)",
		help: cliHelp{
			example: `cscli macros list -a
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros
cscli macros inspect crowdsecurity/http-macros crowdsecurity/ssh-macros
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros
`,
		},
		installHelp: cliHelp{
			example: `# Install some macros.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run -o raw

# Download only, to be installed later.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros -i
cscli macros install crowdsecurity/http-macros crowdsecurity/ssh-macros --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some macros.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros --purge

# Remove tainted items.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros -i
cscli macros remove crowdsecurity/http-macros crowdsecurity/ssh-macros --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some macros. If they are not currently installed, they are downloaded but not installed.
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros -i
cscli macros upgrade crowdsecurity/http-macros crowdsecurity/ssh-macros --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state and ancestor collections of macros (installed or not).
cscli macros inspect crowdsecurity/http-macros crowdsecurity/ssh-macros

# Display difference between a tainted item and the latest one.
cscli macros inspect crowdsecurity/http-macros --diff

# Reverse the above diff
cscli macros inspect crowdsecurity/http-macros --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) macros.
cscli macros list

# List all available macros (installed or not).
cscli macros list -a

# List specific macros (installed or not).
cscli macros list crowdsecurity/http-macros crowdsecurity/ssh-macros`,
		},
	}
}
