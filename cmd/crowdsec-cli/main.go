package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fatih/color"
	cc "github.com/ivanpirog/coloredcobra"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

var (
	ConfigFilePath string
	csConfig       *csconfig.Config
	dbClient       *database.Client
)

type configGetter func() *csconfig.Config

var mergedConfig string

type cliRoot struct {
	logTrace     bool
	logDebug     bool
	logInfo      bool
	logWarn      bool
	logErr       bool
	outputColor  string
	outputFormat string
	// flagBranch overrides the value in csConfig.Cscli.HubBranch
	flagBranch string
}

func newCliRoot() *cliRoot {
	return &cliRoot{}
}

// cfg() is a helper function to get the configuration loaded from config.yaml,
// we pass it to subcommands because the file is not read until the Execute() call
func (cli *cliRoot) cfg() *csconfig.Config {
	return csConfig
}

// wantedLogLevel returns the log level requested in the command line flags.
func (cli *cliRoot) wantedLogLevel() log.Level {
	switch {
	case cli.logTrace:
		return log.TraceLevel
	case cli.logDebug:
		return log.DebugLevel
	case cli.logInfo:
		return log.InfoLevel
	case cli.logWarn:
		return log.WarnLevel
	case cli.logErr:
		return log.ErrorLevel
	default:
		return log.InfoLevel
	}
}

// loadConfigFor loads the configuration file for the given sub-command.
// If the sub-command does not need it, it returns a default configuration.
func loadConfigFor(command string) (*csconfig.Config, string, error) {
	noNeedConfig := []string{
		"doc",
		"help",
		"completion",
		"version",
		"hubtest",
	}

	if !slices.Contains(noNeedConfig, command) {
		log.Debugf("Using %s as configuration file", ConfigFilePath)

		config, merged, err := csconfig.NewConfig(ConfigFilePath, false, false, true)
		if err != nil {
			return nil, "", err
		}

		// set up directory for trace files
		if err := trace.Init(filepath.Join(config.ConfigPaths.DataDir, "trace")); err != nil {
			return nil, "", fmt.Errorf("while setting up trace directory: %w", err)
		}

		return config, merged, nil
	}

	return csconfig.NewDefaultConfig(), "", nil
}

// initialize is called before the subcommand is executed.
func (cli *cliRoot) initialize() {
	var err error

	log.SetLevel(cli.wantedLogLevel())

	csConfig, mergedConfig, err = loadConfigFor(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// recap of the enabled feature flags, because logging
	// was not enabled when we set them from envvars
	if fflist := csconfig.ListFeatureFlags(); fflist != "" {
		log.Debugf("Enabled feature flags: %s", fflist)
	}

	if cli.flagBranch != "" {
		csConfig.Cscli.HubBranch = cli.flagBranch
	}

	if cli.outputFormat != "" {
		csConfig.Cscli.Output = cli.outputFormat
	}

	if csConfig.Cscli.Output == "" {
		csConfig.Cscli.Output = "human"
	}

	if csConfig.Cscli.Output != "human" && csConfig.Cscli.Output != "json" && csConfig.Cscli.Output != "raw" {
		log.Fatalf("output format '%s' not supported: must be one of human, json, raw", csConfig.Cscli.Output)
	}

	if csConfig.Cscli.Output == "json" {
		log.SetFormatter(&log.JSONFormatter{})
		log.SetLevel(log.ErrorLevel)
	} else if csConfig.Cscli.Output == "raw" {
		log.SetLevel(log.ErrorLevel)
	}

	if cli.outputColor != "" {
		csConfig.Cscli.Color = cli.outputColor

		if cli.outputColor != "yes" && cli.outputColor != "no" && cli.outputColor != "auto" {
			log.Fatalf("output color %s unknown", cli.outputColor)
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

func (cli *cliRoot) colorize(cmd *cobra.Command) {
	cc.Init(&cc.Config{
		RootCmd:         cmd,
		Headings:        cc.Yellow,
		Commands:        cc.Green + cc.Bold,
		CmdShortDescr:   cc.Cyan,
		Example:         cc.Italic,
		ExecName:        cc.Bold,
		Aliases:         cc.Bold + cc.Italic,
		FlagsDataType:   cc.White,
		Flags:           cc.Green,
		FlagsDescr:      cc.Cyan,
		NoExtraNewlines: true,
		NoBottomNewline: true,
	})
	cmd.SetOut(color.Output)
}

func (cli *cliRoot) NewCommand() *cobra.Command {
	// set the formatter asap and worry about level later
	logFormatter := &log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true}
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

	cli.colorize(cmd)

	/*don't sort flags so we can enforce order*/
	cmd.Flags().SortFlags = false

	pflags := cmd.PersistentFlags()
	pflags.SortFlags = false

	pflags.StringVarP(&ConfigFilePath, "config", "c", csconfig.DefaultConfigPath("config.yaml"), "path to crowdsec config file")
	pflags.StringVarP(&cli.outputFormat, "output", "o", "", "Output format: human, json, raw")
	pflags.StringVarP(&cli.outputColor, "color", "", "auto", "Output color: yes, no, auto")
	pflags.BoolVar(&cli.logDebug, "debug", false, "Set logging to debug")
	pflags.BoolVar(&cli.logInfo, "info", false, "Set logging to info")
	pflags.BoolVar(&cli.logWarn, "warning", false, "Set logging to warning")
	pflags.BoolVar(&cli.logErr, "error", false, "Set logging to error")
	pflags.BoolVar(&cli.logTrace, "trace", false, "Set logging to trace")
	pflags.StringVar(&cli.flagBranch, "branch", "", "Override hub branch on github")

	if err := pflags.MarkHidden("branch"); err != nil {
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
		cobra.OnInitialize(cli.initialize)
	}

	cmd.AddCommand(NewCLIDoc().NewCommand(cmd))
	cmd.AddCommand(NewCLIVersion().NewCommand())
	cmd.AddCommand(NewCLIConfig(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIHub(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIMetrics(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIDashboard(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIDecisions(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIAlerts(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLISimulation(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIBouncers(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIMachines(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLICapi(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLILapi(cli.cfg).NewCommand())
	cmd.AddCommand(NewCompletionCmd())
	cmd.AddCommand(NewCLIConsole(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIExplain(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIHubTest(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLINotifications(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLISupport().NewCommand())
	cmd.AddCommand(NewCLIPapi(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLICollection(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIParser(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIScenario(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIPostOverflow(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIContext(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIAppsecConfig(cli.cfg).NewCommand())
	cmd.AddCommand(NewCLIAppsecRule(cli.cfg).NewCommand())

	if fflag.CscliSetup.IsEnabled() {
		cmd.AddCommand(NewSetupCmd())
	}

	return cmd
}

func main() {
	cmd := newCliRoot().NewCommand()
	if err := cmd.Execute(); err != nil {
		color.New(color.FgRed).Fprint(os.Stderr, "Error: ")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
