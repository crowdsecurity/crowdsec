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
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type configGetter func() *csconfig.Config

type cliConsole struct {
	cfg configGetter
}

func New(cfg configGetter) *cliConsole {
	return &cliConsole{
		cfg: cfg,
	}
}

func (cli *cliConsole) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		Args:              cobra.MinimumNArgs(1),
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

func (cli *cliConsole) enroll(ctx context.Context, key string, name string, overwrite bool, tags []string, opts []string) error {
	cfg := cli.cfg()
	password := strfmt.Password(cfg.API.Server.OnlineClient.Credentials.Password)

	apiURL, err := url.Parse(cfg.API.Server.OnlineClient.Credentials.URL)
	if err != nil {
		return fmt.Errorf("could not parse CAPI URL: %w", err)
	}

	enableOpts := []string{csconfig.SEND_MANUAL_SCENARIOS, csconfig.SEND_TAINTED_SCENARIOS}

	if len(opts) != 0 {
		for _, opt := range opts {
			valid := false

			if opt == "all" {
				enableOpts = csconfig.CONSOLE_CONFIGS
				break
			}

			for _, availableOpt := range csconfig.CONSOLE_CONFIGS {
				if opt != availableOpt {
					continue
				}

				valid = true
				enable := true

				for _, enabledOpt := range enableOpts {
					if opt == enabledOpt {
						enable = false
						continue
					}
				}

				if enable {
					enableOpts = append(enableOpts, opt)
				}

				break
			}

			if !valid {
				return fmt.Errorf("option %s doesn't exist", opt)
			}
		}
	}

	hub, err := require.Hub(cfg, nil)
	if err != nil {
		return err
	}

	c, _ := apiclient.NewClient(&apiclient.Config{
		MachineID:     cli.cfg().API.Server.OnlineClient.Credentials.Login,
		Password:      password,
		Scenarios:     hub.GetInstalledListForAPI(),
		URL:           apiURL,
		VersionPrefix: "v3",
	})

	resp, err := c.Auth.EnrollWatcher(ctx, key, name, tags, overwrite)
	if err != nil {
		return fmt.Errorf("could not enroll instance: %w", err)
	}

	if resp.Response.StatusCode == http.StatusOK && !overwrite {
		log.Warning("Instance already enrolled. You can use '--overwrite' to force enroll")
		return nil
	}

	if err := cli.setConsoleOpts(enableOpts, true); err != nil {
		return err
	}

	for _, opt := range enableOpts {
		log.Infof("Enabled %s : %s", opt, csconfig.CONSOLE_CONFIGS_HELP[opt])
	}

	log.Info("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
	log.Info("Please restart crowdsec after accepting the enrollment.")

	return nil
}

func (cli *cliConsole) newEnrollCmd() *cobra.Command {
	name := ""
	overwrite := false
	tags := []string{}
	opts := []string{}

	cmd := &cobra.Command{
		Use:   "enroll [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: fmt.Sprintf(`cscli console enroll YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] --tags [tag_1] --tags [tag_2] YOUR-ENROLL-KEY
		cscli console enroll --enable context,manual YOUR-ENROLL-KEY

		valid options are : %s,all (see 'cscli console status' for details)`, strings.Join(csconfig.CONSOLE_CONFIGS, ",")),
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.enroll(cmd.Context(), args[0], name, overwrite, tags, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&name, "name", "n", "", "Name to display in the console")
	flags.BoolVarP(&overwrite, "overwrite", "", false, "Force enroll the instance")
	flags.StringSliceVarP(&tags, "tags", "t", tags, "Tags to display in the console")
	flags.StringSliceVarP(&opts, "enable", "e", opts, "Enable console options")

	return cmd
}

func (cli *cliConsole) newEnableCmd() *cobra.Command {
	var enableAll bool

	cmd := &cobra.Command{
		Use:     "enable [option]",
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

func (cli *cliConsole) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Shows status of the console options",
		Example:           `sudo cscli console status`,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			consoleCfg := cfg.API.Server.ConsoleConfig
			switch cfg.Cscli.Output {
			case "human":
				cmdConsoleStatusTable(color.Output, cfg.Cscli.Color, *consoleCfg)
			case "json":
				out := map[string](*bool){
					csconfig.SEND_MANUAL_SCENARIOS:  consoleCfg.ShareManualDecisions,
					csconfig.SEND_CUSTOM_SCENARIOS:  consoleCfg.ShareCustomScenarios,
					csconfig.SEND_TAINTED_SCENARIOS: consoleCfg.ShareTaintedScenarios,
					csconfig.SEND_CONTEXT:           consoleCfg.ShareContext,
					csconfig.CONSOLE_MANAGEMENT:     consoleCfg.ConsoleManagement,
				}
				data, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to serialize configuration: %w", err)
				}
				fmt.Println(string(data))
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
					{csconfig.CONSOLE_MANAGEMENT, strconv.FormatBool(*consoleCfg.ConsoleManagement)},
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
			/*for each flag check if it's already set before setting it*/
			if consoleCfg.ConsoleManagement != nil && *consoleCfg.ConsoleManagement == wanted {
				log.Debugf("%s already set to %t", csconfig.CONSOLE_MANAGEMENT, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.CONSOLE_MANAGEMENT, wanted)
				consoleCfg.ConsoleManagement = ptr.Of(wanted)
			}

			if cfg.API.Server.OnlineClient.Credentials != nil {
				changed := false
				if wanted && cfg.API.Server.OnlineClient.Credentials.PapiURL == "" {
					changed = true
					cfg.API.Server.OnlineClient.Credentials.PapiURL = types.PAPIBaseURL
				} else if !wanted && cfg.API.Server.OnlineClient.Credentials.PapiURL != "" {
					changed = true
					cfg.API.Server.OnlineClient.Credentials.PapiURL = ""
				}

				if changed {
					fileContent, err := yaml.Marshal(cfg.API.Server.OnlineClient.Credentials)
					if err != nil {
						return fmt.Errorf("cannot serialize credentials: %w", err)
					}

					log.Infof("Updating credentials file: %s", cfg.API.Server.OnlineClient.CredentialsFilePath)

					err = os.WriteFile(cfg.API.Server.OnlineClient.CredentialsFilePath, fileContent, 0o600)
					if err != nil {
						return fmt.Errorf("cannot write credentials file: %w", err)
					}
				}
			}
		case csconfig.SEND_CUSTOM_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if consoleCfg.ShareCustomScenarios != nil && *consoleCfg.ShareCustomScenarios == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				consoleCfg.ShareCustomScenarios = ptr.Of(wanted)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if consoleCfg.ShareTaintedScenarios != nil && *consoleCfg.ShareTaintedScenarios == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				consoleCfg.ShareTaintedScenarios = ptr.Of(wanted)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if consoleCfg.ShareManualDecisions != nil && *consoleCfg.ShareManualDecisions == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				consoleCfg.ShareManualDecisions = ptr.Of(wanted)
			}
		case csconfig.SEND_CONTEXT:
			/*for each flag check if it's already set before setting it*/
			if consoleCfg.ShareContext != nil && *consoleCfg.ShareContext == wanted {
				log.Debugf("%s already set to %t", csconfig.SEND_CONTEXT, wanted)
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
				consoleCfg.ShareContext = ptr.Of(wanted)
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
