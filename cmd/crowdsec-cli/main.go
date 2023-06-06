package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	cc "github.com/ivanpirog/coloredcobra"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"golang.org/x/exp/slices"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

var trace_lvl, dbg_lvl, nfo_lvl, wrn_lvl, err_lvl bool

var ConfigFilePath string
var csConfig *csconfig.Config
var dbClient *database.Client

var OutputFormat string
var OutputColor string

var downloadOnly bool
var forceAction bool
var purge bool
var all bool

var prometheusURL string

var mergedConfig string

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

	if !slices.Contains(NoNeedConfig, os.Args[1]) {
		csConfig, mergedConfig, err = csconfig.NewConfig(ConfigFilePath, false, false, true)
		if err != nil {
			log.Fatal(err)
		}
		log.Debugf("Using %s as configuration file", ConfigFilePath)
		if err := csConfig.LoadCSCLI(); err != nil {
			log.Fatal(err)
		}
	} else {
		csConfig = csconfig.NewDefaultConfig()
	}

	// recap of the enabled feature flags, because logging
	// was not enabled when we set them from envvars
	if fflist := csconfig.ListFeatureFlags(); fflist != "" {
		log.Debugf("Enabled feature flags: %s", fflist)
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

	if OutputColor != "" {
		csConfig.Cscli.Color = OutputColor
		if OutputColor != "yes" && OutputColor != "no" && OutputColor != "auto" {
			log.Fatalf("output color %s unknown", OutputColor)
		}
	}
}

var validArgs = []string{
	"scenarios", "parsers", "collections", "capi", "lapi", "postoverflows", "machines",
	"metrics", "bouncers", "alerts", "decisions", "simulation", "hub", "dashboard",
	"config", "completion", "version", "console", "notifications", "support",
}

func prepender(filename string) string {
	const header = `---
id: %s
title: %s
---
`
	name := filepath.Base(filename)
	base := strings.TrimSuffix(name, path.Ext(name))
	return fmt.Sprintf(header, base, strings.ReplaceAll(base, "_", " "))
}

func linkHandler(name string) string {
	return fmt.Sprintf("/cscli/%s", name)
}

var (
	NoNeedConfig = []string{
		"help",
		"completion",
		"version",
		"hubtest",
	}
)

func main() {
	// set the formatter asap and worry about level later
	logFormatter := &log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true}
	log.SetFormatter(logFormatter)

	if err := fflag.RegisterAllFeatures(); err != nil {
		log.Fatalf("failed to register features: %s", err)
	}

	if err := csconfig.LoadFeatureFlagsEnv(log.StandardLogger()); err != nil {
		log.Fatalf("failed to set feature flags from env: %s", err)
	}

	var rootCmd = &cobra.Command{
		Use:   "cscli",
		Short: "cscli allows you to manage crowdsec",
		Long: `cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.`,
		ValidArgs:         validArgs,
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		/*TBD examples*/
	}

	cc.Init(&cc.Config{
		RootCmd:       rootCmd,
		Headings:      cc.Yellow,
		Commands:      cc.Green + cc.Bold,
		CmdShortDescr: cc.Cyan,
		Example:       cc.Italic,
		ExecName:      cc.Bold,
		Aliases:       cc.Bold + cc.Italic,
		FlagsDataType: cc.White,
		Flags:         cc.Green,
		FlagsDescr:    cc.Cyan,
	})
	rootCmd.SetOut(color.Output)

	var cmdDocGen = &cobra.Command{
		Use:               "doc",
		Short:             "Generate the documentation in `./doc/`. Directory must exist.",
		Args:              cobra.ExactArgs(0),
		Hidden:            true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := doc.GenMarkdownTreeCustom(rootCmd, "./doc/", prepender, linkHandler); err != nil {
				return fmt.Errorf("Failed to generate cobra doc: %s", err)
			}
			return nil
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
	rootCmd.PersistentFlags().StringVarP(&OutputFormat, "output", "o", "", "Output format: human, json, raw.")
	rootCmd.PersistentFlags().StringVarP(&OutputColor, "color", "", "auto", "Output color: yes, no, auto.")
	rootCmd.PersistentFlags().BoolVar(&dbg_lvl, "debug", false, "Set logging to debug.")
	rootCmd.PersistentFlags().BoolVar(&nfo_lvl, "info", false, "Set logging to info.")
	rootCmd.PersistentFlags().BoolVar(&wrn_lvl, "warning", false, "Set logging to warning.")
	rootCmd.PersistentFlags().BoolVar(&err_lvl, "error", false, "Set logging to error.")
	rootCmd.PersistentFlags().BoolVar(&trace_lvl, "trace", false, "Set logging to trace.")

	rootCmd.PersistentFlags().StringVar(&cwhub.HubBranch, "branch", "", "Override hub branch on github")
	if err := rootCmd.PersistentFlags().MarkHidden("branch"); err != nil {
		log.Fatalf("failed to hide flag: %s", err)
	}

	// Look for "-c /path/to/config.yaml"
	// This duplicates the logic in cobra, but we need to do it before
	// because feature flags can change which subcommands are available.
	for i, arg := range os.Args {
		if arg == "-c" || arg == "--config" {
			if len(os.Args) > i+1 {
				ConfigFilePath = os.Args[i+1]
			}
		}
	}

	if err := csconfig.LoadFeatureFlagsFile(ConfigFilePath, log.StandardLogger()); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
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
	rootCmd.AddCommand(NewNotificationsCmd())
	rootCmd.AddCommand(NewSupportCmd())

	if fflag.CscliSetup.IsEnabled() {
		rootCmd.AddCommand(NewSetupCmd())
	}

	if fflag.PapiClient.IsEnabled() {
		rootCmd.AddCommand(NewPapiCmd())
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
