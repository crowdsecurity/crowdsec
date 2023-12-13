package main

import (
	"os"

	"github.com/fatih/color"
	cc "github.com/ivanpirog/coloredcobra"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"slices"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

var trace_lvl, dbg_lvl, nfo_lvl, wrn_lvl, err_lvl bool

var ConfigFilePath string
var csConfig *csconfig.Config
var dbClient *database.Client

var OutputFormat string
var OutputColor string

var mergedConfig string

// flagBranch overrides the value in csConfig.Cscli.HubBranch
var flagBranch = ""

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
		log.Debugf("Using %s as configuration file", ConfigFilePath)
		csConfig, mergedConfig, err = csconfig.NewConfig(ConfigFilePath, false, false, true)
		if err != nil {
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

	if flagBranch != "" {
		csConfig.Cscli.HubBranch = flagBranch
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

// list of valid subcommands for the shell completion
var validArgs = []string{
	"alerts", "appsec-configs", "appsec-rules", "bouncers", "capi", "collections",
	"completion", "config", "console", "contexts", "dashboard", "decisions", "explain",
	"hub", "hubtest", "lapi", "machines", "metrics", "notifications", "parsers",
	"postoverflows", "scenarios", "simulation", "support", "version",
}

var NoNeedConfig = []string{
	"doc",
	"help",
	"completion",
	"version",
	"hubtest",
}

func main() {
	// set the formatter asap and worry about level later
	logFormatter := &log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true}
	log.SetFormatter(logFormatter)

	if err := fflag.RegisterAllFeatures(); err != nil {
		log.Fatalf("failed to register features: %s", err)
	}

	if err := csconfig.LoadFeatureFlagsEnv(log.StandardLogger()); err != nil {
		log.Fatalf("failed to set feature flags from env: %s", err)
	}

	cmd := &cobra.Command{
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
		RootCmd:       cmd,
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
	cmd.SetOut(color.Output)

	cmd.PersistentFlags().StringVarP(&ConfigFilePath, "config", "c", csconfig.DefaultConfigPath("config.yaml"), "path to crowdsec config file")
	cmd.PersistentFlags().StringVarP(&OutputFormat, "output", "o", "", "Output format: human, json, raw")
	cmd.PersistentFlags().StringVarP(&OutputColor, "color", "", "auto", "Output color: yes, no, auto")
	cmd.PersistentFlags().BoolVar(&dbg_lvl, "debug", false, "Set logging to debug")
	cmd.PersistentFlags().BoolVar(&nfo_lvl, "info", false, "Set logging to info")
	cmd.PersistentFlags().BoolVar(&wrn_lvl, "warning", false, "Set logging to warning")
	cmd.PersistentFlags().BoolVar(&err_lvl, "error", false, "Set logging to error")
	cmd.PersistentFlags().BoolVar(&trace_lvl, "trace", false, "Set logging to trace")

	cmd.PersistentFlags().StringVar(&flagBranch, "branch", "", "Override hub branch on github")
	if err := cmd.PersistentFlags().MarkHidden("branch"); err != nil {
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
	cmd.Flags().SortFlags = false
	cmd.PersistentFlags().SortFlags = false

	cmd.AddCommand(NewCLIDoc().NewCommand(cmd))
	cmd.AddCommand(NewCLIVersion().NewCommand())
	cmd.AddCommand(NewConfigCmd())
	cmd.AddCommand(NewCLIHub().NewCommand())
	cmd.AddCommand(NewMetricsCmd())
	cmd.AddCommand(NewCLIDashboard().NewCommand())
	cmd.AddCommand(NewCLIDecisions().NewCommand())
	cmd.AddCommand(NewCLIAlerts().NewCommand())
	cmd.AddCommand(NewCLISimulation().NewCommand())
	cmd.AddCommand(NewCLIBouncers().NewCommand())
	cmd.AddCommand(NewCLIMachines().NewCommand())
	cmd.AddCommand(NewCLICapi().NewCommand())
	cmd.AddCommand(NewLapiCmd())
	cmd.AddCommand(NewCompletionCmd())
	cmd.AddCommand(NewConsoleCmd())
	cmd.AddCommand(NewCLIExplain().NewCommand())
	cmd.AddCommand(NewCLIHubTest().NewCommand())
	cmd.AddCommand(NewCLINotifications().NewCommand())
	cmd.AddCommand(NewCLISupport().NewCommand())
	cmd.AddCommand(NewCLIPapi().NewCommand())
	cmd.AddCommand(NewCLICollection().NewCommand())
	cmd.AddCommand(NewCLIParser().NewCommand())
	cmd.AddCommand(NewCLIScenario().NewCommand())
	cmd.AddCommand(NewCLIPostOverflow().NewCommand())
	cmd.AddCommand(NewCLIContext().NewCommand())
	cmd.AddCommand(NewCLIAppsecConfig().NewCommand())
	cmd.AddCommand(NewCLIAppsecRule().NewCommand())

	if fflag.CscliSetup.IsEnabled() {
		cmd.AddCommand(NewSetupCmd())
	}

	if fflag.PapiClient.IsEnabled() {
		cmd.AddCommand(NewCLIPapi().NewCommand())
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
