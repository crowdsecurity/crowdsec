package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func NewConsoleCmd() *cobra.Command {
	var cmdConsole = &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				var fdErr *fs.PathError
				if errors.As(err, &fdErr) {
					log.Fatalf("Unable to load Local API : %s", fdErr)
				}
				if err != nil {
					log.Fatalf("Unable to load required Local API Configuration : %s", err)
				}
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("No configuration for Central API (CAPI) in '%s'", *csConfig.FilePath)
			}
			if csConfig.API.Server.OnlineClient.Credentials == nil {
				log.Fatal("You must configure Central API (CAPI) with `cscli capi register` before accessing console features.")
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
		Run: func(cmd *cobra.Command, args []string) {
			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiURL, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("Could not parse CAPI URL : %s", err)
			}

			if err := csConfig.LoadHub(); err != nil {
				log.Fatal(err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Info("Run 'sudo cscli hub update' to get the hub index")
			}

			scenarios, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err)
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
				log.Fatalf("Could not enroll instance: %s", err)
			}
			if resp.Response.StatusCode == 200 && !overwrite {
				log.Warning("Instance already enrolled. You can use '--overwrite' to force enroll")
				return
			}

			SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true)
			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			log.Infof("Enabled tainted&manual alerts sharing, see 'cscli console status'.")
			log.Infof("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
			log.Infof("Please restart crowdsec after accepting the enrollment.")
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
		Run: func(cmd *cobra.Command, args []string) {
			if enableAll {
				SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true)
				log.Infof("All features have been enabled successfully")
			} else {
				if len(args) == 0 {
					log.Fatalf("You must specify at least one feature to enable")
				}
				SetConsoleOpts(args, true)
				log.Infof("%v have been enabled", args)
			}
			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			log.Infof(ReloadMessage())
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
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if disableAll {
				SetConsoleOpts(csconfig.CONSOLE_CONFIGS, false)
			} else {
				SetConsoleOpts(args, false)
			}

			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			if disableAll {
				log.Infof("All features have been disabled")
			} else {
				log.Infof("%v have been disabled", args)
			}
			log.Infof(ReloadMessage())
		},
	}
	cmdDisable.Flags().BoolVarP(&disableAll, "all", "a", false, "Disable all console options")
	cmdConsole.AddCommand(cmdDisable)

	cmdConsoleStatus := &cobra.Command{
		Use:               "status [option]",
		Short:             "Shows status of one or all console options",
		Example:           `sudo cscli console status`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			switch csConfig.Cscli.Output {
			case "human":
				cmdConsoleStatusTable(color.Output, *csConfig)
			case "json":
				data, err := json.MarshalIndent(csConfig.API.Server.ConsoleConfig, "", "  ")
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			case "raw":
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"option", "enabled"})
				if err != nil {
					log.Fatal(err)
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
						log.Fatal(err)
					}
				}
				csvwriter.Flush()
			}
		},
	}
	cmdConsole.AddCommand(cmdConsoleStatus)

	return cmdConsole
}

func SetConsoleOpts(args []string, wanted bool) {
	for _, arg := range args {
		switch arg {
		case csconfig.CONSOLE_MANAGEMENT:
			if !fflag.PapiClient.IsEnabled() {
				continue
			}
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
						log.Fatalf("Cannot marshal credentials: %s", err)
					}
					log.Infof("Updating credentials file: %s", csConfig.API.Server.OnlineClient.CredentialsFilePath)
					err = os.WriteFile(csConfig.API.Server.OnlineClient.CredentialsFilePath, fileContent, 0600)
					if err != nil {
						log.Fatalf("Cannot write credentials file: %s", err)
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
			log.Fatalf("unknown flag %s", arg)
		}
	}

}
