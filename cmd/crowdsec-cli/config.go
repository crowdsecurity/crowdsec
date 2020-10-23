package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:   "config [command]",
		Short: "Allows to view current config",
		Args:  cobra.ExactArgs(0),
	}
	var cmdConfigShow = &cobra.Command{
		Use:   "show",
		Short: "Displays current config",
		Long:  `Displays the current cli configuration.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if OutputFormat == "json" {
				log.WithFields(log.Fields{
					"crowdsec_configuration_file": csConfig.Self,
					"data_folder":                 csConfig.Crowdsec.DataDir,
				}).Warning("Current config")
			} else {
				x, err := yaml.Marshal(csConfig.ConfigPaths)
				if err != nil {
					log.Fatalf("failed to marshal current configuration : %v", err)
				}
				fmt.Printf("%s", x)
				x, err = yaml.Marshal(csConfig.API.Client)
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
