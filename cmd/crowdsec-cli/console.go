package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/enescakir/emoji"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func IsInSlice(a string, b []string) bool {
	for _, v := range b {
		if a == v {
			return true
		}
	}
	return false
}

func FetchScenariosListFromDB() ([]string, error) {
	scenarios := make([]string, 0)
	machines, err := dbClient.ListMachines()
	if err != nil {
		return nil, fmt.Errorf("while listing machines: %s", err)
	}
	//merge all scenarios together
	for _, v := range machines {
		machineScenarios := strings.Split(v.Scenarios, ",")
		log.Debugf("%d scenarios for machine %d", len(machineScenarios), v.ID)
		for _, sv := range machineScenarios {
			if !IsInSlice(sv, scenarios) && sv != "" {
				scenarios = append(scenarios, sv)
			}
		}
	}
	log.Debugf("Returning list of scenarios : %+v", scenarios)
	return scenarios, nil
}

func NewConsoleCmd() *cobra.Command {
	var cmdConsole = &cobra.Command{
		Use:               "console [action]",
		Short:             "Manage interaction with Crowdsec console (https://app.crowdsec.net)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil {
				var fdErr *fs.PathError
				if errors.As(err, &fdErr) {
					log.Fatalf("Unable to load Local API : %s", fdErr)
				} else {
					log.Fatalf("Unable to load required Local API Configuration : %s", err)
				}
			}

			if csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if csConfig.API.Server.OnlineClient == nil {
				log.Fatalf("no configuration for Central API (CAPI) in '%s'", *csConfig.FilePath)
			}
			if csConfig.API.Server.OnlineClient.Credentials == nil {
				log.Fatal("You must configure Central API (CAPI) with `cscli capi register` before enrolling your instance")
			}

			return nil
		},
	}

	cmdEnroll := &cobra.Command{
		Use:   "enroll [enroll-key]",
		Short: "Enroll this instance to https://app.crowdsec.net [requires local API]",
		Long: `
Enroll this instance to https://app.crowdsec.net
		
You can get your enrollment key by creating an account on https://app.crowdsec.net.
After running this command your will need to validate the enrollment in the webapp.`,
		Example: `cscli console enroll YOUR-ENROLL-KEY
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
				log.Fatalf(err.Error())
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}

			scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err.Error())
			}

			if len(scenarios) == 0 {
				scenarios = make([]string, 0)
			}

			c, _ := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:      password,
				Scenarios:     scenarios,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v2",
			})
			_, err = c.Auth.EnrollWatcher(context.Background(), args[0])
			if err != nil {
				log.Fatalf("Could not enroll instance: %s", err)
			}
			log.Infof("Watcher successfully enrolled. Visit https://app.crowdsec.net to accept it.")
		},
	}
	cmdConsole.AddCommand(cmdEnroll)

	var enableAll, disableAll bool

	cmdEnable := &cobra.Command{
		Use:     "enable [feature-flag]",
		Short:   "Enable a feature flag",
		Example: "enable alerts-tainted",
		Long: `
Enable given information push to the central API. Allows to empower the console`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if enableAll {
				SetConsoleOpts(csconfig.CONSOLE_CONFIGS, true)
			} else {
				SetConsoleOpts(args, true)
			}

			if err := csConfig.API.Server.DumpConsoleConfig(); err != nil {
				log.Fatalf("failed writing console config : %s", err)
			}
			if enableAll {
				log.Infof("All features have been enabled successfully")
			} else {
				log.Infof("%v have been enabled", args)
			}
			log.Infof(ReloadMessage())
		},
	}
	cmdEnable.Flags().BoolVarP(&enableAll, "all", "a", false, "Enable all feature flags")
	cmdConsole.AddCommand(cmdEnable)

	cmdDisable := &cobra.Command{
		Use:     "disable [feature-flag]",
		Short:   "Disable a feature flag",
		Example: "disable alerts-tainted",
		Long: `
Disable given information push to the central API.`,
		ValidArgs:         csconfig.CONSOLE_CONFIGS,
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
	cmdDisable.Flags().BoolVarP(&disableAll, "all", "a", false, "Enable all feature flags")
	cmdConsole.AddCommand(cmdDisable)

	cmdConsoleStatus := &cobra.Command{
		Use:               "status [feature-flag]",
		Short:             "Shows status of one or all feature flags",
		Example:           "status alerts-tainted",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			switch csConfig.Cscli.Output {
			case "human":
				table := tablewriter.NewWriter(os.Stdout)

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Option Name", "Activated", "Description"})
				for _, option := range csconfig.CONSOLE_CONFIGS {
					switch option {
					case csconfig.SEND_CUSTOM_SCENARIOS:
						activated := fmt.Sprintf("%s", emoji.CrossMark)
						if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios == true {
							activated = fmt.Sprintf("%s", emoji.CheckMarkButton)
						}
						table.Append([]string{option, activated, "Send alerts from custom scenarios to the console"})
					case csconfig.SEND_MANUAL_SCENARIOS:
						activated := fmt.Sprintf("%s", emoji.CrossMark)
						if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions == true {
							activated = fmt.Sprintf("%s", emoji.CheckMarkButton)
						}
						table.Append([]string{option, activated, "Send manual decisions to the console"})
					case csconfig.SEND_TAINTED_SCENARIOS:
						activated := fmt.Sprintf("%s", emoji.CrossMark)
						if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios == true {
							activated = fmt.Sprintf("%s", emoji.CheckMarkButton)
						}
						table.Append([]string{option, activated, "Send alerts from tainted scenarios to the console"})
					}
				}
				table.Render()
			case "json": //TBD : fix this
				data, err := json.MarshalIndent(csConfig.API.Server.ConsoleConfig, "", "  ")
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			case "raw":
				data, err := yaml.Marshal(csConfig.API.Server.ConsoleConfig)
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			}
		},
	}

	cmdConsole.AddCommand(cmdConsoleStatus)

	cmdConsoleSync := &cobra.Command{
		Use:               "sync",
		Short:             "Sync current decisions to console",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Errorf("This command requires direct database access (must be run on the local API machine)")
				log.Fatalf(err.Error())
			}
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}

			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
			apiurl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				log.Fatalf("parsing api url ('%s'): %s", csConfig.API.Server.OnlineClient.Credentials.URL, err)
			}

			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to load hub index : %s", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
			if err != nil {
				log.Fatalf("failed to get scenarios : %s", err.Error())
			}
			if len(scenarios) == 0 {
				log.Fatalf("no scenarios installed, abort")
			}

			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:      csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:       password,
				UserAgent:      fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:            apiurl,
				VersionPrefix:  "v2",
				Scenarios:      scenarios,
				UpdateScenario: FetchScenariosListFromDB,
			})
			if err != nil {
				log.Fatalf("init default client: %s", err)
			}

			filter := make(map[string][]string)
			filter["has_active_decision"] = []string{"true"}
			alertsWithDecisions, err := dbClient.QueryAlertWithFilter(filter)
			if err != nil {
				log.Fatalf(err.Error())
			}

			alertList := make([]*models.Alert, 0)
			for _, alert := range alertsWithDecisions {
				startAt := alert.StartedAt.String()
				StopAt := alert.StoppedAt.String()
				formatedAlert := models.Alert{
					ID:              int64(alert.ID),
					MachineID:       machineID,
					CreatedAt:       alert.CreatedAt.Format(time.RFC3339),
					Scenario:        &alert.Scenario,
					ScenarioVersion: &alert.ScenarioVersion,
					ScenarioHash:    &alert.ScenarioHash,
					Message:         &alert.Message,
					EventsCount:     &alert.EventsCount,
					StartAt:         &startAt,
					StopAt:          &StopAt,
					Capacity:        &alert.Capacity,
					Leakspeed:       &alert.LeakSpeed,
					Simulated:       &alert.Simulated,
					Source: &models.Source{
						Scope:     &alert.SourceScope,
						Value:     &alert.SourceValue,
						IP:        alert.SourceIp,
						Range:     alert.SourceRange,
						AsNumber:  alert.SourceAsNumber,
						AsName:    alert.SourceAsName,
						Cn:        alert.SourceCountry,
						Latitude:  alert.SourceLatitude,
						Longitude: alert.SourceLongitude,
					},
				}
				for _, decisionItem := range alert.Edges.Decisions {
					duration := decisionItem.Until.Sub(time.Now()).String()
					formatedAlert.Decisions = append(formatedAlert.Decisions, &models.Decision{
						Duration:  &duration, // transform into time.Time ?
						Scenario:  &decisionItem.Scenario,
						Type:      &decisionItem.Type,
						Scope:     &decisionItem.Scope,
						Value:     &decisionItem.Value,
						Origin:    &decisionItem.Origin,
						Simulated: formatedAlert.Simulated,
						ID:        int64(decisionItem.ID),
					})
				}
				alertList = append(alertList, &formatedAlert)
			}
			_, _, err = Client.Decisions.SyncDecisions(context.Background(), alertList)
			if err != nil {
				log.Fatalf("unable to sync decisions with console: %s", err.Error())
			}
			log.Infof("Decisions have been synchronized successfully")
		},
	}

	cmdConsole.AddCommand(cmdConsoleSync)

	return cmdConsole
}

func SetConsoleOpts(args []string, wanted bool) {
	for _, arg := range args {
		switch arg {
		case csconfig.SEND_CUSTOM_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareCustomScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareCustomScenarios == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_CUSTOM_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareCustomScenarios = types.BoolPtr(wanted)
			}
		case csconfig.SEND_TAINTED_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_TAINTED_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareTaintedScenarios = types.BoolPtr(wanted)
			}
		case csconfig.SEND_MANUAL_SCENARIOS:
			/*for each flag check if it's already set before setting it*/
			if csConfig.API.Server.ConsoleConfig.ShareManualDecisions != nil {
				if *csConfig.API.Server.ConsoleConfig.ShareManualDecisions == wanted {
					log.Infof("%s already set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				} else {
					log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
					*csConfig.API.Server.ConsoleConfig.ShareManualDecisions = wanted
				}
			} else {
				log.Infof("%s set to %t", csconfig.SEND_MANUAL_SCENARIOS, wanted)
				csConfig.API.Server.ConsoleConfig.ShareManualDecisions = types.BoolPtr(wanted)
			}
		default:
			log.Fatalf("unknown flag %s", arg)
		}
	}

}
