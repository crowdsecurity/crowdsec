package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

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
var csConfig *csconfig.Config
var dbClient *database.Client

var OutputFormat string

var downloadOnly bool
var forceAction bool
var purge bool
var all bool
var restoreOldBackup bool

var prometheusURL string

func initConfig() {
	var err error
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
	logFormatter := &log.TextFormatter{TimestampFormat: "02-01-2006 03:04:05 PM", FullTimestamp: true}
	log.SetFormatter(logFormatter)
	csConfig, err = csconfig.NewConfig(ConfigFilePath, false, false)
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Debugf("Using %s as configuration file", ConfigFilePath)
	if err := csConfig.LoadCSCLI(); err != nil {
		log.Fatalf(err.Error())
	}

	if csConfig.Cscli == nil {
		log.Fatalf("missing 'cscli' configuration in '%s', exiting", ConfigFilePath)
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
		log.SetFormatter(&log.JSONFormatter{})
		log.SetLevel(log.ErrorLevel)
	} else if csConfig.Cscli.Output == "raw" {
		log.SetLevel(log.ErrorLevel)
	}

}

var validArgs = []string{
	"scenarios", "parsers", "collections", "capi", "lapi", "postoverflows", "machines",
	"metrics", "bouncers", "alerts", "decisions", "simulation", "hub", "dashboard",
	"config", "completion", "version", "console",
}

func prepender(filename string) string {
	const header = `---
id: %s
title: %s
---
`
	name := filepath.Base(filename)
	base := strings.TrimSuffix(name, path.Ext(name))
	return fmt.Sprintf(header, base, strings.Replace(base, "_", " ", -1))
}

func linkHandler(name string) string {
	return fmt.Sprintf("/cscli/%s", name)
}

func main() {

	var rootCmd = &cobra.Command{
		Use:   "cscli",
		Short: "cscli allows you to manage crowdsec",
		Long: `cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.`,
		ValidArgs:         validArgs,
		DisableAutoGenTag: true,
		/*TBD examples*/
	}
	var cmdDocGen = &cobra.Command{
		Use:               "doc",
		Short:             "Generate the documentation in `./doc/`. Directory must exist.",
		Args:              cobra.ExactArgs(0),
		Hidden:            true,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := doc.GenMarkdownTreeCustom(rootCmd, "./doc/", prepender, linkHandler); err != nil {
				log.Fatalf("Failed to generate cobra doc: %s", err.Error())
			}
		},
	}
	rootCmd.AddCommand(cmdDocGen)
	/*usage*/
	var cmdVersion = &cobra.Command{
		Use:               "version",
		Short:             "Display version and exit.",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			cwversion.Show()
		},
	}
	rootCmd.AddCommand(cmdVersion)

	rootCmd.PersistentFlags().StringVarP(&ConfigFilePath, "config", "c", csconfig.DefaultConfigPath("config.yaml"), "path to crowdsec config file")
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

	if len(os.Args) > 1 && os.Args[1] != "completion" && os.Args[1] != "version" && os.Args[1] != "help" {
		cobra.OnInitialize(initConfig)
	}

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
	rootCmd.AddCommand(NewCompletionCmd())
	rootCmd.AddCommand(NewConsoleCmd())
	rootCmd.AddCommand(NewExplainCmd())
	rootCmd.AddCommand(NewHubTestCmd())
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("While executing root command : %s", err)
	}
}
