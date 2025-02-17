package cliitem

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewParser(cfg configGetter) *cliItem {
	return &cliItem{
		cfg:       cfg,
		name:      cwhub.PARSERS,
		singular:  "parser",
		oneOrMore: "parser(s)",
		help: cliHelp{
			example: `cscli parsers list -a
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs
`,
		},
		installHelp: cliHelp{
			example: `# Install some parsers.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run -o raw

# Download only, to be installed later.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs --download-only

# Install over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs -i
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs --interactive`,
		},
		removeHelp: cliHelp{
			example: `# Uninstall some parsers.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run -o raw

# Uninstall and also remove the downloaded files.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs --purge

# Remove tainted items.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs -i
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs --interactive`,
		},
		upgradeHelp: cliHelp{
			example: `# Upgrade some parsers. If they are not currently installed, they are downloaded but not installed.
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs

# Show the execution plan without changing anything - compact output sorted by type and name.
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run

# Show the execution plan without changing anything - verbose output sorted by execution order.
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs --dry-run -o raw

# Upgrade over tainted items. Can be used to restore or repair after local modifications or missing dependencies.
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs -i
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs --interactive`,
		},
		inspectHelp: cliHelp{
			example: `# Display metadata, state, metrics and ancestor collections of parsers (installed or not).
cscli parsers inspect crowdsecurity/httpd-logs crowdsecurity/sshd-logs

# Don't collect metrics (avoid error if crowdsec is not running).
cscli parsers inspect crowdsecurity/httpd-logs --no-metrics

# Display difference between a tainted item and the latest one.
cscli parsers inspect crowdsecurity/httpd-logs --diff

# Reverse the above diff
cscli parsers inspect crowdsecurity/httpd-logs --diff --rev`,
		},
		listHelp: cliHelp{
			example: `# List enabled (installed) parsers.
cscli parsers list

# List all available parsers (installed or not).
cscli parsers list -a

# List specific parsers (installed or not).
cscli parsers list crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
	}
}
