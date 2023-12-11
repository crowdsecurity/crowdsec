package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCLIPostOverflow() *cliItem {
	return &cliItem{
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
			example: `cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		removeHelp: cliHelp{
			example: `cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		upgradeHelp: cliHelp{
			example: `cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		inspectHelp: cliHelp{
			example: `cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		},
		listHelp: cliHelp{
			example: `cscli postoverflows list
cscli postoverflows list -a
cscli postoverflows list crowdsecurity/cdn-whitelist crowdsecurity/rdns

List only enabled postoverflows unless "-a" or names are specified.`,
		},
	}
}
