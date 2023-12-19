package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func NewConsoleCmd() *cobra.Command {
	var cmdConsole = &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := require.LAPI(csConfig); err != nil {
				return err
			}
			if err := require.CAPI(csConfig); err != nil {
				return err
			}
			if err := require.CAPIRegistered(csConfig); err != nil {
				return err
			}
			return nil
		},
	}

	name := ""
	overwrite := false
	tags := []string{}

	cmdEnroll := &cobra.Command{
		Use:   "enroll [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: `cscli console enroll YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] YOUR-ENROLL-KEY
		cscli console enroll --name [instance_name] --tags [tag_1] --tags [tag_2] YOUR-ENROLL-KEY
`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiURL, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				return fmt.Errorf("could not parse CAPI URL: %s", err)
			}

			hub, err := require.Hub(csConfig, nil, nil)
			if err != nil {
				return err
			}

			scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
			if err != nil {
				return fmt.Errorf("failed to get installed scenarios: %s", err)
			}

			if len(scenarios) == 0 {
				scenarios = make([]string, 0)
			}

			c, _ := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:      password,
				Scenarios:     scenarios,
				UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
				URL:           apiURL,
				VersionPrefix: "v3",
			})
			resp, err := c.Auth.EnrollWatcher(context.Background(), args[0], name, tags, overwrite)
			if err != nil {
				return fmt.Errorf("could not enroll instance: %s", err)
			}
			if resp.Response.StatusCode == 200 && !overwrite {
				log.Warning("Instance already enrolled. You can use '--overwrite' to force enroll")
				return nil
			}

			if err := SetConsoleOpts([]string{csconfig.SEND_MANUAL_SCENARIOS, csconfig.SEND_TAINTED_SCENARIOS}, true); err != nil {
				return err
			}

			log.Info("Enabled tainted&manual alerts sharing, see 'cscli console status'.")
			log.Info("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
			log.Info("Please restart crowdsec after accepting the enrollment.")
			return nil
		},
	}
	cmdEnroll.Flags().StringVarP(&name, "name", "n", "", "Name to display in the console")
	cmdEnroll.Flags().BoolVarP(&overwrite, "overwrite", "", false, "Force enroll the instance")
	cmdEnroll.Flags().StringSliceVarP(&tags, "tags", "t", tags, "Tags to display in the console")
	cmdConsole.AddCommand(cmdEnroll)

	var enableAll, disableAll bool

	cmdEnable := &cobra.Command{
		Use:     "enable [option]",
		Short:   "Enable a console option",
		Example: "sudo cscli console enable tainted",
		Long: `
Enable given information push to the central API. Allows to empower the console`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if enableAll {
				if err := SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true); err != nil {
					return err
				}
				log.Infof("All features have been enabled successfully")
			} else {
				if len(args) == 0 {
					return fmt.Errorf("you must specify at least one feature to enable")
				}
				if err := SetConsoleOpts(args, true); err != nil {
					return err
				}
				log.Infof("%v have been enabled", args)
			}
			log.Infof(ReloadMessage())
			return nil
		},
	}
	cmdEnable.Flags().BoolVarP(&enableAll, "all", "a", false, "Enable all console options")
	cmdConsole.AddCommand(cmdEnable)

	cmdDisable := &cobra.Command{
		Use:     "disable [option]",
		Short:   "Disable a console option",
		Example: "sudo cscli console disable tainted",
		Long: `
Disable given information push to the central API.`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if disableAll {
				if err := SetConsoleOpts(csconfig.CONSOLE_CONFIGS, false); err != nil {
					return err
				}
				log.Infof("All features have been disabled")
			} else {
				if err := SetConsoleOpts(args, false); err != nil {
					return err
				}
				log.Infof("%v have been disabled", args)
			}

			log.Infof(ReloadMessage())
			return nil
		},
	}
	cmdDisable.Flags().BoolVarP(&disableAll, "all", "a", false, "Disable all console options")
	cmdConsole.AddCommand(cmdDisable)

	cmdConsoleStatus := &cobra.Command{
		Use:               "status",
		Short:             "Shows status of the console options",
		Example:           `sudo cscli console status`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch csConfig.Cscli.Output {
			case "human":
				cmdConsoleStatusTable(color.Output, *csConfig)
			case "json":
				c := csConfig.API.Server.ConsoleConfig
				out := map[string](*bool){
					csconfig.SEND_MANUAL_SCENARIOS:  c.ShareManualDecisions,
					csconfig.SEND_CUSTOM_SCENARIOS:  c.ShareCustomScenarios,
					csconfig.SEND_TAINTED_SCENARIOS: c.ShareTaintedScenarios,
					csconfig.SEND_CONTEXT:           c.ShareContext,
					csconfig.CONSOLE_MANAGEMENT:     c.ConsoleManagement,
				}
				data, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal configuration: %s", err)
				}
				fmt.Println(string(data))
			case "raw":
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"option", "enabled"})
				if err != nil {
					return err
				}

				rows := [][]string{
					{csconfig.SEND_MANUAL_SCENARIOS, fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareManualDecisions)},
					{csconfig.SEND_CUSTOM_SCENARIOS, fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios)},
					{csconfig.SEND_TAINTED_SCENARIOS, fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios)},
					{csconfig.SEND_CONTEXT, fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ShareContext)},
					{csconfig.CONSOLE_MANAGEMENT, fmt.Sprintf("%t", *csConfig.API.Server.ConsoleConfig.ConsoleManagement)},
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
	cmdConsole.AddCommand(cmdConsoleStatus)

	return cmdConsole
}

func dumpConsoleConfig(c *csconfig.LocalApiServerCfg) error {
	out, err := yaml.Marshal(c.ConsoleConfig)
	if err != nil {
		return fmt.Errorf("while marshaling ConsoleConfig (for %s): %w", c.ConsoleConfigPath, err)
	}

	if c.ConsoleConfigPath == "" {
		c.ConsoleConfigPath = csconfig.DefaultConsoleConfigFilePath
		log.Debugf("Empty console_path, defaulting to %s", c.ConsoleConfigPath)
	}

	if err := os.WriteFile(c.ConsoleConfigPath, out, 0o600); err != nil {
		return fmt.Errorf("while dumping console config to %s: %w", c.ConsoleConfigPath, err)
	}

	return nil
}

func SetConsoleOpts(args []string, wanted bool) error {
	for _, arg := range args {
		switch arg {
		case csconfig.CONSOLE_MANAGEMENT:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ConsoleManagement != nil {
				if *csConfig.API.Server.ConsoleConfig.ConsoleManagement == wanted {
					log.Debugf("%s already set to %t", csconfig.CONSOLE_MANAGEMENT, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.CONSOLE_MANAGEMENT, wanted)
					*csConfig.API.Server.ConsoleConfig.ConsoleManagement = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.CONSOLE_MANAGEMENT, wanted)
				csConfig.API.Server.ConsoleConfig.ConsoleManagement = ptr.Of(wanted)
			}
			if csConfig.API.Server.OnlineClient.Credentials != nil {
				changed := false
				if wanted && csConfig.API.Server.OnlineClient.Credentials.PapiURL == "" {
					changed = true
					csConfig.API.Server.OnlineClient.Credentials.PapiURL = types.PAPIBaseURL
				} else if !wanted && csConfig.API.Server.OnlineClient.Credentials.PapiURL != "" {
					changed = true
					csConfig.API.Server.OnlineClient.Credentials.PapiURL = ""
				}
				if changed {
					fileContent, err := yaml.Marshal(csConfig.API.Server.OnlineClient.Credentials)
					if err != nil {
						return fmt.Errorf("cannot marshal credentials: %s", err)
					}
					log.Infof("Updating credentials file: %s", csConfig.API.Server.OnlineClient.CredentialsFilePath)
					err = os.WriteFile(csConfig.API.Server.OnlineClient.CredentialsFilePath, fileContent, 0o600)
					if err != nil {
						return fmt.Errorf("cannot write credentials file: %s", err)
					}
				}
			}
		case csconfig.SEND_CUSTOM_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareCustomScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios == wanted {
					log.Debugf("%s already set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = ptr.Of(wanted)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios == wanted {
					log.Debugf("%s already set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = ptr.Of(wanted)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareManualDecisions != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions == wanted {
					log.Debugf("%s already set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareManualDecisions = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareManualDecisions = ptr.Of(wanted)
			}
		case csconfig.SEND_CONTEXT:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareContext != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareContext == wanted {
					log.Debugf("%s already set to %t", csconfig.SEND_CONTEXT, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareContext = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CONTEXT, wanted)
				csConfig.API.Server.ConsoleConfig.ShareContext = ptr.Of(wanted)
			}
		default:
			return fmt.Errorf("unknown flag %s", arg)
		}
	}

	if err := dumpConsoleConfig(csConfig.API.Server); err != nil {
		return fmt.Errorf("failed writing console config: %s", err)
	}

	return nil
}
