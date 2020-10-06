package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

/*CliCfg is the cli configuration structure, might be unexported*/
type cliConfig struct {
	configured          bool
	ConfigFilePath      string `yaml:"config_file"`
	configFolder        string
	output              string
	HubFolder           string `yaml:"hub_folder"`
	InstallFolder       string
	BackendPluginFolder string `yaml:"backend_folder"`
	DataFolder          string `yaml:"data_folder"`
	SimulationCfgPath   string `yaml:"simulation_path,omitempty"`
	SimulationCfg       *csconfig.SimulationConfig
}

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:   "config [command] <value>",
		Short: "Allows to view/edit cscli config",
		Long: `Allow to configure database plugin path and installation directory.
If no commands are specified, config is in interactive mode.`,
		Example: `- cscli config show
- cscli config prompt`,
		Args: cobra.ExactArgs(1),
	}
	var cmdConfigShow = &cobra.Command{
		Use:   "show",
		Short: "Displays current config",
		Long:  `Displays the current cli configuration.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if config.output == "json" {
				log.WithFields(log.Fields{
					"crowdsec_configuration_file": config.ConfigFilePath,
					"backend_folder":              config.BackendPluginFolder,
					"data_folder":                 config.DataFolder,
				}).Warning("Current config")
			} else {
				x, err := yaml.Marshal(config)
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
