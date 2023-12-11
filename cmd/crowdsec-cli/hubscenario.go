package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCLIScenario() *cliItem {
	return &cliItem{
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
			example: `cscli scenarios install crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		removeHelp: cliHelp{
			example: `cscli scenarios remove crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		upgradeHelp: cliHelp{
			example: `cscli scenarios upgrade crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		inspectHelp: cliHelp{
			example: `cscli scenarios inspect crowdsecurity/ssh-bf crowdsecurity/http-probing`,
		},
		listHelp: cliHelp{
			example: `cscli scenarios list
cscli scenarios list -a
cscli scenarios list crowdsecurity/ssh-bf crowdsecurity/http-probing

List only enabled scenarios unless "-a" or names are specified.`,
		},
	}
}
