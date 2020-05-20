package main

import (
	"io/ioutil"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"gopkg.in/yaml.v2"
)

var dbg_lvl, nfo_lvl, wrn_lvl, err_lvl bool

var config cliConfig

func initConfig() {

	if dbg_lvl {
		log.SetLevel(log.DebugLevel)
	} else if nfo_lvl {
		log.SetLevel(log.InfoLevel)
	} else if wrn_lvl {
		log.SetLevel(log.WarnLevel)
	} else if err_lvl {
		log.SetLevel(log.ErrorLevel)
	}
	if config.output == "json" {
		log.SetLevel(log.WarnLevel)
		log.SetFormatter(&log.JSONFormatter{})
	} else if config.output == "raw" {
		log.SetLevel(log.ErrorLevel)
	}

	if strings.HasPrefix(config.configFolder, "~/") {
		usr, err := user.Current()
		if err != nil {
			log.Fatalf("failed to resolve path ~/ : %s", err)
		}
		config.configFolder = usr.HomeDir + "/" + config.configFolder[2:]
	}
	/*read config*/
	buf, err := ioutil.ReadFile(filepath.Clean(config.configFolder + "/config"))
	if err != nil {
		log.Infof("Failed to open config %s : %s", filepath.Clean(config.configFolder+"/config"), err)
	} else {
		err = yaml.UnmarshalStrict(buf, &config)
		if err != nil {
			log.Fatalf("Failed to parse config %s : %s, please configure", filepath.Clean(config.configFolder+"/config"), err)
		}
		config.InstallFolder = filepath.Clean(config.InstallFolder)
		config.hubFolder = filepath.Clean(config.configFolder + "/hub/")
		config.BackendPluginFolder = filepath.Clean(config.BackendPluginFolder)
		//
		cwhub.Installdir = config.InstallFolder
		cwhub.Cfgdir = config.configFolder
		cwhub.Hubdir = config.hubFolder
		config.configured = true
	}
}

func main() {

	var rootCmd = &cobra.Command{
		Use:   "cscli",
		Short: "cscli allows you to manage crowdsec",
		Long: `cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.`,
		Example: `View/Add/Remove bans:  
 - cscli ban list  
 - cscli ban add ip 1.2.3.4 24h 'go away'  
 - cscli ban del 1.2.3.4  
		
View/Add/Upgrade/Remove scenarios and parsers:  
 - cscli list  
 - cscli install collection crowdsec/linux-web  
 - cscli remove scenario crowdsec/ssh_enum  
 - cscli upgrade --all  

API interaction:
 - cscli api pull
 - cscli api register
 `}
	/*TODO : add a remediation type*/
	var cmdDocGen = &cobra.Command{
		Use:    "doc",
		Short:  "Generate the documentation in `./doc/`. Directory must exist.",
		Args:   cobra.ExactArgs(0),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			doc.GenMarkdownTree(rootCmd, "./doc/")
		},
	}
	rootCmd.AddCommand(cmdDocGen)
	/*usage*/
	var cmdVersion = &cobra.Command{
		Use:    "version",
		Short:  "Display version and exit.",
		Args:   cobra.ExactArgs(0),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			cwversion.Show()
		},
	}
	rootCmd.AddCommand(cmdVersion)

	//rootCmd.PersistentFlags().BoolVarP(&config.simulation, "simulate", "s", false, "No action; perform a simulation of events that would occur based on the current arguments.")
	rootCmd.PersistentFlags().StringVarP(&config.configFolder, "config-dir", "c", "/etc/crowdsec/cscli/", "Configuration directory to use.")
	rootCmd.PersistentFlags().StringVarP(&config.output, "output", "o", "human", "Output format : human, json, raw.")
	rootCmd.PersistentFlags().BoolVar(&dbg_lvl, "debug", false, "Set logging to debug.")
	rootCmd.PersistentFlags().BoolVar(&nfo_lvl, "info", false, "Set logging to info.")
	rootCmd.PersistentFlags().BoolVar(&wrn_lvl, "warning", false, "Set logging to warning.")
	rootCmd.PersistentFlags().BoolVar(&err_lvl, "error", false, "Set logging to error.")

	cobra.OnInitialize(initConfig)
	/*don't sort flags so we can enforce order*/
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.AddCommand(NewBanCmds())
	rootCmd.AddCommand(NewConfigCmd())
	rootCmd.AddCommand(NewInstallCmd())
	rootCmd.AddCommand(NewListCmd())
	rootCmd.AddCommand(NewRemoveCmd())
	rootCmd.AddCommand(NewUpdateCmd())
	rootCmd.AddCommand(NewUpgradeCmd())
	rootCmd.AddCommand(NewAPICmd())
	rootCmd.AddCommand(NewMetricsCmd())
	rootCmd.AddCommand(NewBackupCmd())
	rootCmd.AddCommand(NewDashboardCmd())
	rootCmd.AddCommand(NewInspectCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("While executing root command : %s", err)
	}
}
