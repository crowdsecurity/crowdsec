package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewContext(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.CONTEXTS,
		singular:  "context",
		oneOrMore: "context(s)",
		help: cliHelp{
			example: `cscli contexts list -a
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet
cscli contexts inspect crowdsecurity/bf_base crowdsecurity/fortinet
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet
`,
		},
		installHelp: cliHelp{
			example: `# Install some contexts.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet --dry-run -o raw

# Download only, to be installed later.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet -i
cscli contexts install crowdsecurity/bf_base crowdsecurity/fortinet --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some contexts.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet --purge

# Remove tainted items.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet -i
cscli contexts remove crowdsecurity/bf_base crowdsecurity/fortinet --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some contexts. If they are not currently installed, they are downloaded but not installed.
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet -i
cscli contexts upgrade crowdsecurity/bf_base crowdsecurity/fortinet --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state and ancestor collections of contexts (installed or not).
cscli contexts inspect crowdsecurity/bf_base crowdsecurity/fortinet

# Display difference between a tainted item and the latest one.
cscli contexts inspect crowdsecurity/bf_base --diff

# Reverse the above diff
cscli contexts inspect crowdsecurity/bf_base --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) contexts.
cscli contexts list

# List all available contexts (installed or not).
cscli contexts list -a

# List specific contexts (installed or not).
cscli contexts list crowdsecurity/bf_base crowdsecurity/fortinet`,
		},
	}
}
