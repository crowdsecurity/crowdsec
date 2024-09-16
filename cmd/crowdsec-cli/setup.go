//go:build !no_cscli_setup
package main

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup"
)

func (cli *cliRoot) addSetup(cmd *cobra.Command) {
	if fflag.CscliSetup.IsEnabled() {
		cmd.AddCommand(clisetup.New(cli.cfg).NewCommand())
	}
	component.Register("cscli_setup")
}
