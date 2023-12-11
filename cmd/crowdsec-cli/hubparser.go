package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCLIParser() *cliItem {
	return &cliItem{
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
			example: `cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		removeHelp: cliHelp{
			example: `cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		upgradeHelp: cliHelp{
			example: `cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		},
		inspectHelp: cliHelp{
			example: `cscli parsers inspect crowdsecurity/httpd-logs crowdsecurity/sshd-logs`,
		},
		listHelp: cliHelp{
			example: `cscli parsers list
cscli parsers list -a
cscli parsers list crowdsecurity/caddy-logs crowdsecurity/sshd-logs

List only enabled parsers unless "-a" or names are specified.`,
		},
	}
}
