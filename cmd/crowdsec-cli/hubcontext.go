package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCLIContext() *cliItem {
	return &cliItem{
		name:      cwhub.CONTEXTS,
		singular:  "context",
		oneOrMore: "context(s)",
		help: cliHelp{
			example: `cscli contexts list -a
cscli contexts install crowdsecurity/yyy crowdsecurity/zzz
cscli contexts inspect crowdsecurity/yyy crowdsecurity/zzz
cscli contexts upgrade crowdsecurity/yyy crowdsecurity/zzz
cscli contexts remove crowdsecurity/yyy crowdsecurity/zzz
`,
		},
		installHelp: cliHelp{
			example: `cscli contexts install crowdsecurity/yyy crowdsecurity/zzz`,
		},
		removeHelp: cliHelp{
			example: `cscli contexts remove crowdsecurity/yyy crowdsecurity/zzz`,
		},
		upgradeHelp: cliHelp{
			example: `cscli contexts upgrade crowdsecurity/yyy crowdsecurity/zzz`,
		},
		inspectHelp: cliHelp{
			example: `cscli contexts inspect crowdsecurity/yyy crowdsecurity/zzz`,
		},
		listHelp: cliHelp{
			example: `cscli contexts list
cscli contexts list -a
cscli contexts list crowdsecurity/yyy crowdsecurity/zzz

List only enabled contexts unless "-a" or names are specified.`,
		},
	}
}
