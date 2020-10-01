package main

import (
	"os/user"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
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

	csConfig := csconfig.NewCrowdSecConfig()
	if err := csConfig.LoadConfigurationFile(&config.ConfigFilePath); err != nil {
		log.Fatalf(err.Error())
	}
	config.configFolder = filepath.Clean(csConfig.CsCliFolder)

	if strings.HasPrefix(config.configFolder, "~/") {
		usr, err := user.Current()
		if err != nil {
			log.Fatalf("failed to resolve path ~/ : %s", err)
		}
		config.configFolder = usr.HomeDir + "/" + config.configFolder[2:]
	}

	/*read config*/
	config.InstallFolder = filepath.Clean(csConfig.ConfigFolder)
	config.HubFolder = filepath.Clean(config.configFolder + "/hub/")
	if csConfig.OutputConfig == nil {
		log.Fatalf("Missing backend plugin configuration in %s", config.ConfigFilePath)
	}
	config.BackendPluginFolder = filepath.Clean(csConfig.OutputConfig.BackendFolder)
	config.DataFolder = filepath.Clean(csConfig.DataFolder)
	//
	cwhub.Installdir = config.InstallFolder
	cwhub.Cfgdir = config.configFolder
	cwhub.Hubdir = config.HubFolder
	config.configured = true
	config.SimulationCfg = csConfig.SimulationCfg
	config.SimulationCfgPath = csConfig.SimulationCfgPath
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
			if err := doc.GenMarkdownTree(rootCmd, "./doc/"); err != nil {
				log.Fatalf("Failed to generate cobra doc")
			}
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
	rootCmd.PersistentFlags().StringVarP(&config.ConfigFilePath, "config", "c", "/etc/crowdsec/config/default.yaml", "path to crowdsec config file")

	rootCmd.PersistentFlags().StringVarP(&config.output, "output", "o", "human", "Output format : human, json, raw.")
	rootCmd.PersistentFlags().BoolVar(&dbg_lvl, "debug", false, "Set logging to debug.")
	rootCmd.PersistentFlags().BoolVar(&nfo_lvl, "info", false, "Set logging to info.")
	rootCmd.PersistentFlags().BoolVar(&wrn_lvl, "warning", false, "Set logging to warning.")
	rootCmd.PersistentFlags().BoolVar(&err_lvl, "error", false, "Set logging to error.")

	rootCmd.PersistentFlags().StringVar(&cwhub.HubBranch, "branch", "master", "Override hub branch on github")
	if err := rootCmd.PersistentFlags().MarkHidden("branch"); err != nil {
		log.Fatalf("failed to make branch hidden : %s", err)
	}
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
	rootCmd.AddCommand(NewSimulationCmds())
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("While executing root command : %s", err)
	}
}
