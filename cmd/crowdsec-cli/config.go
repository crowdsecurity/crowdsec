package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

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

func interactiveCfg() error {
	var err error
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("crowdsec installation directory (default: /etc/crowdsec/config/): ")
	config.InstallFolder, err = reader.ReadString('\n')
	config.InstallFolder = strings.Replace(config.InstallFolder, "\n", "", -1) //CRLF to LF (windows)
	if config.InstallFolder == "" {
		config.InstallFolder = "/etc/crowdsec/config/"
	}
	if err != nil {
		log.Fatalf("failed to read input : %v", err.Error())
	}

	fmt.Print("crowdsec backend plugin directory (default: /etc/crowdsec/plugin/backend): ")
	config.BackendPluginFolder, err = reader.ReadString('\n')
	config.BackendPluginFolder = strings.Replace(config.BackendPluginFolder, "\n", "", -1) //CRLF to LF (windows)
	if config.BackendPluginFolder == "" {
		config.BackendPluginFolder = "/etc/crowdsec/plugin/backend"
	}
	if err != nil {
		log.Fatalf("failed to read input : %v", err.Error())
	}
	if err := writeCfg(); err != nil {
		log.Fatalf("failed writting configuration file : %s", err)
	}
	return nil
}

func writeCfg() error {

	if config.configFolder == "" {
		return fmt.Errorf("config dir is unset")
	}

	config.hubFolder = config.configFolder + "/hub/"
	if _, err := os.Stat(config.hubFolder); os.IsNotExist(err) {

		log.Warningf("creating skeleton!")
		if err := os.MkdirAll(config.hubFolder, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create missing directory : '%s'", config.hubFolder)
		}
	}
	out := path.Join(config.configFolder, "/config")
	configYaml, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed marshaling config: %s", err)
	}
	err = ioutil.WriteFile(out, configYaml, 0644)
	if err != nil {
		return fmt.Errorf("failed to write to %s : %s", out, err)
	}
	log.Infof("wrote config to %s ", out)
	return nil
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
	var cmdConfigInterctive = &cobra.Command{
		Use:   "prompt",
		Short: "Prompt for configuration values in an interactive fashion",
		Long:  `Start interactive configuration of cli. It will successively ask for install dir, db path.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			err := interactiveCfg()
			if err != nil {
				log.Fatalf("Failed to run interactive config : %s", err)
			}
			log.Warningf("Configured, please run update.")
		},
	}
	cmdConfig.AddCommand(cmdConfigInterctive)
	var cmdConfigInstalldir = &cobra.Command{
		Use:   "installdir [value]",
		Short: `Configure installation directory`,
		Long:  `Configure the installation directory of crowdsec, such as /etc/crowdsec/config/`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			config.InstallFolder = args[0]
			if err := writeCfg(); err != nil {
				log.Fatalf("failed writting configuration: %s", err)
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigInstalldir)

	var cmdConfigBackendFolder = &cobra.Command{
		Use:   "backend [value]",
		Short: `Configure installation directory`,
		Long:  `Configure the backend plugin directory of crowdsec, such as /etc/crowdsec/plugins/backend`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			config.BackendPluginFolder = args[0]
			if err := writeCfg(); err != nil {
				log.Fatalf("failed writting configuration: %s", err)
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigBackendFolder)

	return cmdConfig
}
