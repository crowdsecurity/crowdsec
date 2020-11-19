package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var trace_lvl, dbg_lvl, nfo_lvl, wrn_lvl, err_lvl bool

var ConfigFilePath string
var csConfig *csconfig.GlobalConfig
var dbClient *database.Client

var OutputFormat string

var downloadOnly bool
var forceInstall bool
var forceUpgrade bool
var removeAll bool
var purgeRemove bool
var upgradeAll bool
var listAll bool
var restoreOldBackup bool

var prometheusURL string

func initConfig() {

	if trace_lvl {
		log.SetLevel(log.TraceLevel)
	} else if dbg_lvl {
		log.SetLevel(log.DebugLevel)
	} else if nfo_lvl {
		log.SetLevel(log.InfoLevel)
	} else if wrn_lvl {
		log.SetLevel(log.WarnLevel)
	} else if err_lvl {
		log.SetLevel(log.ErrorLevel)
	}

	csConfig = csconfig.NewConfig()

	log.Debugf("Using %s as configuration file", ConfigFilePath)
	if err := csConfig.LoadConfigurationFile(ConfigFilePath); err != nil {
		log.Fatalf(err.Error())
	}
	if cwhub.HubBranch == "" && csConfig.Cscli.HubBranch != "" {
		cwhub.HubBranch = csConfig.Cscli.HubBranch
	}
	if OutputFormat != "" {
		csConfig.Cscli.Output = OutputFormat
		if OutputFormat != "json" && OutputFormat != "raw" && OutputFormat != "human" {
			log.Fatalf("output format %s unknown", OutputFormat)
		}
	}
	if csConfig.Cscli.Output == "" {
		csConfig.Cscli.Output = "human"
	}

	if csConfig.Cscli.Output == "json" {
		log.SetLevel(log.WarnLevel)
		log.SetFormatter(&log.JSONFormatter{})
	} else if csConfig.Cscli.Output == "raw" {
		log.SetLevel(log.ErrorLevel)
	}

}

func main() {

	var rootCmd = &cobra.Command{
		Use:   "cscli",
		Short: "cscli allows you to manage crowdsec",
		Long: `cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.`,
		/*TBD examples*/
	}
	var cmdDocGen = &cobra.Command{
		Use:    "doc",
		Short:  "Generate the documentation in `./doc/`. Directory must exist.",
		Args:   cobra.ExactArgs(0),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := doc.GenMarkdownTree(rootCmd, "./doc/"); err != nil {
				log.Fatalf("Failed to generate cobra doc: %s", err.Error())
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

	rootCmd.PersistentFlags().StringVarP(&ConfigFilePath, "config", "c", "/etc/crowdsec/config.yaml", "path to crowdsec config file")
	rootCmd.PersistentFlags().StringVarP(&OutputFormat, "output", "o", "", "Output format : human, json, raw.")
	rootCmd.PersistentFlags().BoolVar(&dbg_lvl, "debug", false, "Set logging to debug.")
	rootCmd.PersistentFlags().BoolVar(&nfo_lvl, "info", false, "Set logging to info.")
	rootCmd.PersistentFlags().BoolVar(&wrn_lvl, "warning", false, "Set logging to warning.")
	rootCmd.PersistentFlags().BoolVar(&err_lvl, "error", false, "Set logging to error.")
	rootCmd.PersistentFlags().BoolVar(&trace_lvl, "trace", false, "Set logging to trace.")

	rootCmd.PersistentFlags().StringVar(&cwhub.HubBranch, "branch", "", "Override hub branch on github")
	if err := rootCmd.PersistentFlags().MarkHidden("branch"); err != nil {
		log.Fatalf("failed to make branch hidden : %s", err)
	}
	cobra.OnInitialize(initConfig)
	/*don't sort flags so we can enforce order*/
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.AddCommand(NewConfigCmd())
	rootCmd.AddCommand(NewHubCmd())
	rootCmd.AddCommand(NewMetricsCmd())
	rootCmd.AddCommand(NewDashboardCmd())
	rootCmd.AddCommand(NewDecisionsCmd())
	rootCmd.AddCommand(NewAlertsCmd())
	//	rootCmd.AddCommand(NewInspectCmd())
	rootCmd.AddCommand(NewSimulationCmds())
	rootCmd.AddCommand(NewBouncersCmd())
	rootCmd.AddCommand(NewMachinesCmd())
	rootCmd.AddCommand(NewParsersCmd())
	rootCmd.AddCommand(NewScenariosCmd())
	rootCmd.AddCommand(NewCollectionsCmd())
	rootCmd.AddCommand(NewPostOverflowsCmd())
	rootCmd.AddCommand(NewCapiCmd())
	rootCmd.AddCommand(NewLapiCmd())
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("While executing root command : %s", err)
	}
}
