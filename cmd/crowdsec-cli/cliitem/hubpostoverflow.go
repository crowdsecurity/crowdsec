package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewPostOverflow(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.POSTOVERFLOWS,
		singular:  "postoverflow",
		oneOrMore: "postoverflow(s)",
		help: cliHelp{
			example: `cscli postoverflows list -a
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns
`,
		},
		installHelp: cliHelp{
			example: `# Install some postoverflows.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns --dry-run -o raw

# Download only, to be installed later.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns -i
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some postoverflows.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns --purge

# Remove tainted items.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns -i
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some postoverflows. If they are not currently installed, they are downloaded but not installed.
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss -i
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdnss --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state and ancestor collections of postoverflows (installed or not).
cscli postoverflows inspect crowdsecurity/cdn-whitelist

# Display difference between a tainted item and the latest one.
cscli postoverflows inspect crowdsecurity/cdn-whitelist --diff

# Reverse the above diff
cscli postoverflows inspect crowdsecurity/cdn-whitelist --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) postoverflows.
cscli postoverflows list

# List all available postoverflows (installed or not).
cscli postoverflows list -a

# List specific postoverflows (installed or not).
cscli postoverflows list crowdsecurity/cdn-whitelists crowdsecurity/rdns`,
		},
	}
}
