//go:build no_cscli_setup
package main

import (
	"github.com/spf13/cobra"
)

func (cli *cliRoot) addSetup(_ *cobra.Command) {
}
