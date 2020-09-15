package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:   "config [command] <value>",
		Short: "Allows to view/edit cscli config",
		Long: `Allow to configure database plugin path and installation directory.
If no commands are specified, config is in interactive mode.`,
		Example: ` - cscli config show
- cscli config prompt`,
		Args: cobra.ExactArgs(1),
	}
	var cmdConfigShow = &cobra.Command{
		Use:   "show",
		Short: "Displays current config",
		Long:  `Displays the current cli configuration.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if csconfig.GConfig.Cscli.Output == "json" {
				log.WithFields(log.Fields{
					"crowdsec_configuration_file": csconfig.GConfig.Self,
					"data_folder":                 csconfig.GConfig.Crowdsec.DataDir,
				}).Warning("Current config")
			} else {
				x, err := yaml.Marshal(csconfig.GConfig.Cscli)
				if err != nil {
					log.Fatalf("failed to marshal current configuration : %v", err)
				}
				fmt.Printf("%s", x)
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigShow)
	return cmdConfig
}
