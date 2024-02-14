package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCLICollection() *cliItem {
	return &cliItem{
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
			example: `cscli collections install crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		removeHelp: cliHelp{
			example: `cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		upgradeHelp: cliHelp{
			example: `cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		inspectHelp: cliHelp{
			example: `cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables`,
		},
		listHelp: cliHelp{
			example: `cscli collections list
cscli collections list -a
cscli collections list crowdsecurity/http-cve crowdsecurity/iptables

List only enabled collections unless "-a" or names are specified.`,
		},
	}
}
