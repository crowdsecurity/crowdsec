package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCollection(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.COLLECTIONS,
		singular:  "collection",
		oneOrMore: "collection(s)",
		help: cliHelp{
			example: `cscli collections list -a
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables
`,
		},
		installHelp: cliHelp{
			example: `# Install some collections.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables --dry-run -o raw

# Download only, to be installed later.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables -i
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some collections.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables --purge

# Remove tainted items.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables -i
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some collections. If they are not currently installed, they are downloaded but not installed.
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables -i
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, metrics and dependencies of collections (installed or not).
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables

# Don't collect metrics (avoid error if crowdsec is not running).
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables --no-metrics

# Display difference between a tainted item and the latest one, or the reason for the taint if it's a dependency.
cscli collections inspect crowdsecurity/http-cve --diff

# Reverse the above diff
cscli collections inspect crowdsecurity/http-cve --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) collections.
cscli collections list

# List all available collections (installed or not).
cscli collections list -a

# List specific collections (installed or not).
cscli collections list crowdsecurity/http-cve crowdsecurity/iptables`,
		},
	}
}
