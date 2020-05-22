package main

import (
	"fmt"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

/*CliCfg is the cli configuration structure, might be unexported*/
type cliConfig struct {
	configured          bool
	configFolder        string `yaml:"cliconfig,omitempty"` /*overload ~/.cscli/*/
	output              string /*output is human, json*/
	hubFolder           string
	InstallFolder       string `yaml:"installdir"` /*/etc/crowdsec/*/
	BackendPluginFolder string `yaml:"backend"`
	dbPath              string
}

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:   "config [command] <value>",
		Short: "Allows to view/edit cscli config",
		Long: `Allow to configure sqlite path and installation directory.
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
			if config.output == "json" {
				log.WithFields(log.Fields{
					"installdir": config.InstallFolder,
					"cliconfig":  path.Join(config.configFolder, "/config"),
				}).Warning("Current config")
			} else {
				x, err := yaml.Marshal(config)
				if err != nil {
					log.Fatalf("failed to marshal current configuration : %v", err)
				}
				fmt.Printf("%s", x)
				fmt.Printf("#cliconfig: %s", path.Join(config.configFolder, "/config"))
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigShow)
	return cmdConfig
}
