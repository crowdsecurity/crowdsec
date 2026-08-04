package cliconsole

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/consolestatus"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type cliConsole struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliConsole {
	return &cliConsole{
		cfg: cfg,
	}
}

func (cli *cliConsole) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := require.LAPI(cfg); err != nil {
				return err
			}

			if err := require.CAPI(cfg); err != nil {
				return err
			}

			return require.CAPIRegistered(cfg)
		},
	}

	cmd.AddCommand(cli.newEnrollCmd())
	cmd.AddCommand(cli.newEnableCmd())
	cmd.AddCommand(cli.newDisableCmd())
	cmd.AddCommand(cli.newStatusCmd())

	return cmd
}

func (cli *cliConsole) enroll(ctx context.Context, key string, name string, overwrite bool, tags []string, opts []string, autoEnroll bool) error {
	cfg := cli.cfg()
	password := strfmt.Password(cfg.API.Server.OnlineClient.Credentials.Password)

	apiURL, err := url.Parse(cfg.API.Server.OnlineClient.Credentials.URL)
	if err != nil {
		return fmt.Errorf("could not parse CAPI URL: %w", err)
	}

	hub, err := require.Hub(cfg, nil)
	if err != nil {
		return err
	}

	c := apiclient.NewClient(&apiclient.Config{
		MachineID:     cli.cfg().API.Server.OnlineClient.Credentials.Login,
		Password:      password,
		URL:           apiURL,
		VersionPrefix: "v3",
		UpdateScenario: func(_ context.Context) ([]string, error) {
			return hub.GetInstalledListForAPI(), nil
		},
	})

	autoResp, rawResp, err := c.Auth.EnrollWatcher(ctx, key, name, tags, overwrite, autoEnroll)
	if err != nil {
		return fmt.Errorf("could not enroll instance: %w", err)
	}

	if rawResp.Response.StatusCode == http.StatusOK {
		if autoEnroll {
			log.Warn("The instance is already enrolled in an organization; transfer it using https://app.crowdsec.net/.")
			return nil
		}
		if !overwrite {
			log.Warning("Instance already enrolled. You can use '--overwrite' to force enroll")
			return nil
		}
	}

	if autoEnroll {
		bold := color.New(color.Bold)
		log.Infof("Please visit the following URL to enroll your instance: %s", bold.Sprint(autoResp.Url))
		log.Infof("This link is valid for the next %s.", time.Until(time.UnixMilli(autoResp.ExpiresAt)).Round(time.Minute))
		log.Info("Please restart crowdsec after accepting the enrollment.")

	} else {
		log.Info("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
		log.Info("Please restart crowdsec after accepting the enrollment.")
	}

	if err := cli.setConsoleOpts(opts, true); err != nil {
		return err
	}

	for _, opt := range opts {
		log.Infof("Enabled %s : %s", opt, csconfig.CONSOLE_CONFIGS_HELP[opt])
	}

	return nil
}

func optionFilterEnable(opts []string, enableOpts []string) ([]string, error) {
	if len(enableOpts) == 0 {
		return opts, nil
	}

	for _, opt := range enableOpts {
		if opt == "all" {
			opts = append(opts, csconfig.CONSOLE_CONFIGS...)
			// keep validating the rest of the option names
			continue
		}

		if opt == csconfig.CONSOLE_MANAGEMENT {
			log.Warnf("'%s' is deprecated and has no effect: decision management is enabled automatically based on your console plan", csconfig.CONSOLE_MANAGEMENT)
			continue
		}

		if !slices.Contains(csconfig.CONSOLE_CONFIGS, opt) {
			return nil, fmt.Errorf("option %s doesn't exist", opt)
		}

		opts = append(opts, opt)
	}

	opts = slicetools.Deduplicate(opts)

	return opts, nil
}

func optionFilterDisable(opts []string, disableOpts []string) ([]string, error) {
	if len(disableOpts) == 0 {
		return opts, nil
	}

	for _, opt := range disableOpts {
		if opt == "all" {
			opts = []string{}
			// keep validating the rest of the option names
			continue
		}

		if opt == csconfig.CONSOLE_MANAGEMENT {
			log.Warnf("'%s' is deprecated and has no effect: decision management is enabled automatically based on your console plan", csconfig.CONSOLE_MANAGEMENT)
			continue
		}

		if !slices.Contains(csconfig.CONSOLE_CONFIGS, opt) {
			return nil, fmt.Errorf("option %s doesn't exist", opt)
		}

		// discard all elements == opt

		j := 0

		for _, o := range opts {
			if o != opt {
				opts[j] = o
				j++
			}
		}

		opts = opts[:j]
	}

	return opts, nil
}

func (*cliConsole) getDefaultInstanceName() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Warnf("Could not get machine hostname: %s. Defaulting to machine id as instance name", err)
		return ""
	}

	return hostname
}

func (cli *cliConsole) newEnrollCmd() *cobra.Command {
	name := ""
	overwrite := false
	quickEnroll := false
	tags := []string{}
	enableOpts := []string{}
	disableOpts := []string{}

	cmd := &cobra.Command{
		Use:   "enroll [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: fmt.Sprintf(`cscli console enroll YOUR-ENROLL-KEY
cscli console enroll --quick
cscli console enroll --quick --name [instance_name]
cscli console enroll --name [instance_name] YOUR-ENROLL-KEY
cscli console enroll --name [instance_name] --tags [tag_1] --tags [tag_2] YOUR-ENROLL-KEY
cscli console enroll --disable context YOUR-ENROLL-KEY

valid options are : %s,all (see 'cscli console status' for details)`, strings.Join(csconfig.CONSOLE_CONFIGS, ",")),
		Args:              args.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !quickEnroll {
				return cmd.Usage()
			}
			if len(args) > 0 && quickEnroll {
				return errors.New("enroll key cannot be specified when using quick enroll")
			}
			key := ""
			if len(args) > 0 {
				key = args[0]
			}
			opts := []string{csconfig.SEND_MANUAL_SCENARIOS, csconfig.SEND_TAINTED_SCENARIOS, csconfig.SEND_CONTEXT}

			opts, err := optionFilterEnable(opts, enableOpts)
			if err != nil {
				return err
			}

			opts, err = optionFilterDisable(opts, disableOpts)
			if err != nil {
				return err
			}

			return cli.enroll(cmd.Context(), key, name, overwrite, tags, opts, quickEnroll)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&name, "name", "n", cli.getDefaultInstanceName(), "Name to display in the console")
	flags.BoolVarP(&overwrite, "overwrite", "", false, "Force enroll the instance")
	flags.StringSliceVarP(&tags, "tags", "t", tags, "Tags to display in the console")
	flags.StringSliceVarP(&enableOpts, "enable", "e", enableOpts, "Enable console options")
	flags.StringSliceVarP(&disableOpts, "disable", "d", disableOpts, "Disable console options")
	flags.BoolVarP(&quickEnroll, "quick", "q", false, "Enrolls the instance without an enroll key by visiting a link to the CrowdSec console.")

	return cmd
}

func (cli *cliConsole) newEnableCmd() *cobra.Command {
	var enableAll bool

	cmd := &cobra.Command{
		Use:     "enable [option]...",
		Short:   "Enable a console option",
		Example: "sudo cscli console enable tainted",
		Long: `
Enable given information push to the central API. Allows to empower the console`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if enableAll {
				if err := cli.setConsoleOpts(csconfig.CONSOLE_CONFIGS, true); err != nil {
					return err
				}

				log.Infof("All features have been enabled successfully")
			} else {
				if len(args) == 0 {
					return errors.New("you must specify at least one feature to enable")
				}

				if err := cli.setConsoleOpts(args, true); err != nil {
					return err
				}

				log.Infof("%v have been enabled", args)
			}

			if reload.UserMessage() != "" {
				log.Info(reload.UserMessage())
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&enableAll, "all", "a", false, "Enable all console options")

	return cmd
}

func (cli *cliConsole) newDisableCmd() *cobra.Command {
	var disableAll bool

	cmd := &cobra.Command{
		Use:     "disable [option]",
		Short:   "Disable a console option",
		Example: "sudo cscli console disable tainted",
		Long: `
Disable given information push to the central API.`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if disableAll {
				if err := cli.setConsoleOpts(csconfig.CONSOLE_CONFIGS, false); err != nil {
					return err
				}

				log.Infof("All features have been disabled")
			} else {
				if len(args) == 0 {
					return errors.New("you must specify at least one feature to disable")
				}

				if err := cli.setConsoleOpts(args, false); err != nil {
					return err
				}

				log.Infof("%v have been disabled", args)
			}

			if msg := reload.UserMessage(); msg != "" {
				log.Info(msg)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&disableAll, "all", "a", false, "Disable all console options")

	return cmd
}

type liveConsoleStatus struct {
	capi               consolestatus.CAPIStatus
	registered         bool
	reachable          bool
	decisionManagement bool
	papi               *consolestatus.PAPIInfo
}

// fetchConsoleStatus queries CAPI (and PAPI when enrolled) for the live console link.
func (cli *cliConsole) fetchConsoleStatus(ctx context.Context, cfg *csconfig.Config) liveConsoleStatus {
	st := liveConsoleStatus{}

	online := cfg.API.Server.OnlineClient

	// load credz here to gracefully handle missing/invalid file.
	if online == nil || online.CredentialsFilePath == "" {
		return st
	}

	if err := online.Load(); err != nil {
		log.Warnf("could not load CAPI credentials: %s", err)
		return st
	}

	if online.Credentials == nil {
		return st
	}

	st.registered = true

	hub, err := require.Hub(cfg, nil)
	if err != nil {
		log.Warnf("could not load hub, skipping live console status: %s", err)
		return st
	}

	db, err := require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		log.Warnf("could not connect to database, skipping live console status: %s", err)
		return st
	}

	cred := online.Credentials

	capi, err := consolestatus.QueryCAPIStatus(ctx, db, hub, cred.URL, cred.Login, cred.Password)
	if err != nil {
		log.Warnf("could not reach Central API (CAPI): %s", err)
		return st
	}

	st.capi = capi
	st.reachable = true

	if !capi.Enrolled {
		return st
	}

	st.decisionManagement = consolestatus.DecisionManagementActive(capi.SubscriptionType)

	papi, err := consolestatus.QueryPAPIInfo(ctx, cfg.API.Server, db)
	if err != nil {
		log.Debugf("could not reach Polling API (PAPI): %s", err)
		return st
	}

	st.papi = &papi

	return st
}

func (cli *cliConsole) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Shows status of the console options",
		Example:           `sudo cscli console status`,
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		// Unlike the other console subcommands, status must run even when the engine is not
		// registered against CAPI or can't reach it.
		// We skip loading online credentials here (they're loaded best-effort in
		// fetchConsoleStatus). This overrides the parent's stricter PersistentPreRunE.
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return require.LAPINoOnlineCreds(cli.cfg())
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			ctx := cmd.Context()
			consoleCfg := cfg.API.Server.ConsoleConfig

			switch cfg.Cscli.Output {
			case "human":
				st := cli.fetchConsoleStatus(ctx, cfg)
				cmdConsoleConnectionTable(color.Output, cfg.Cscli.Color, st)
				cmdConsoleStatusTable(color.Output, cfg.Cscli.Color, *consoleCfg)
			case "json":
				st := cli.fetchConsoleStatus(ctx, cfg)

				console := map[string]any{
					"registered":          st.registered,
					"authenticated":       st.reachable,
					"enrolled":            st.capi.Enrolled,
					"plan":                st.capi.SubscriptionType,
					"decision_management": st.decisionManagement,
				}

				if st.papi != nil {
					console["last_order_received"] = st.papi.LastOrder
					console["papi_categories"] = st.papi.Categories
				}

				out := map[string]any{
					"sharing_options": map[string]*bool{
						csconfig.SEND_MANUAL_SCENARIOS:  consoleCfg.ShareManualDecisions,
						csconfig.SEND_CUSTOM_SCENARIOS:  consoleCfg.ShareCustomScenarios,
						csconfig.SEND_TAINTED_SCENARIOS: consoleCfg.ShareTaintedScenarios,
						csconfig.SEND_CONTEXT:           consoleCfg.ShareContext,
					},
					"console": console,
				}

				data, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to serialize configuration: %w", err)
				}

				fmt.Fprintln(os.Stdout, string(data))
			case "raw":
				csvwriter := csv.NewWriter(os.Stdout)

				err := csvwriter.Write([]string{"option", "enabled"})
				if err != nil {
					return err
				}

				rows := [][]string{
					{csconfig.SEND_MANUAL_SCENARIOS, strconv.FormatBool(*consoleCfg.ShareManualDecisions)},
					{csconfig.SEND_CUSTOM_SCENARIOS, strconv.FormatBool(*consoleCfg.ShareCustomScenarios)},
					{csconfig.SEND_TAINTED_SCENARIOS, strconv.FormatBool(*consoleCfg.ShareTaintedScenarios)},
					{csconfig.SEND_CONTEXT, strconv.FormatBool(*consoleCfg.ShareContext)},
				}
				for _, row := range rows {
					err = csvwriter.Write(row)
					if err != nil {
						return err
					}
				}

				csvwriter.Flush()
			}

			return nil
		},
	}

	return cmd
}

func (cli *cliConsole) dumpConfig() error {
	serverCfg := cli.cfg().API.Server

	out, err := yaml.Marshal(serverCfg.ConsoleConfig)
	if err != nil {
		return fmt.Errorf("while serializing ConsoleConfig (for %s): %w", serverCfg.ConsoleConfigPath, err)
	}

	if serverCfg.ConsoleConfigPath == "" {
		serverCfg.ConsoleConfigPath = csconfig.DefaultConsoleConfigFilePath
		log.Debugf("Empty console_path, defaulting to %s", serverCfg.ConsoleConfigPath)
	}

	if err := os.WriteFile(serverCfg.ConsoleConfigPath, out, 0o600); err != nil {
		return fmt.Errorf("while dumping console config to %s: %w", serverCfg.ConsoleConfigPath, err)
	}

	return nil
}

func (cli *cliConsole) setConsoleOpts(args []string, wanted bool) error {
	cfg := cli.cfg()
	consoleCfg := cfg.API.Server.ConsoleConfig

	for _, arg := range args {
		switch arg {
		case csconfig.CONSOLE_MANAGEMENT:
			// deprecated no-op: decision management is now enabled automatically based on the plan
			log.Warnf("'%s' is deprecated and has no effect: decision management is enabled automatically based on your console plan", csconfig.CONSOLE_MANAGEMENT)
		case csconfig.SEND_CUSTOM_SCENARIOS:
			// for each flag check if it's already set before setting it
			if consoleCfg.ShareCustomScenarios != nil && *consoleCfg.ShareCustomScenarios == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				consoleCfg.ShareCustomScenarios = new(wanted)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			// for each flag check if it's already set before setting it
			if consoleCfg.ShareTaintedScenarios != nil && *consoleCfg.ShareTaintedScenarios == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				consoleCfg.ShareTaintedScenarios = new(wanted)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			// for each flag check if it's already set before setting it
			if consoleCfg.ShareManualDecisions != nil && *consoleCfg.ShareManualDecisions == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				consoleCfg.ShareManualDecisions = new(wanted)
			}
		case csconfig.SEND_CONTEXT:
			// for each flag check if it's already set before setting it
			if consoleCfg.ShareContext != nil && *consoleCfg.ShareContext == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_CONTEXT, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
				consoleCfg.ShareContext = new(wanted)
			}
		default:
			return fmt.Errorf("unknown flag %s", arg)
		}
	}

	if err := cli.dumpConfig(); err != nil {
		return fmt.Errorf("failed writing console config: %w", err)
	}

	return nil
}
