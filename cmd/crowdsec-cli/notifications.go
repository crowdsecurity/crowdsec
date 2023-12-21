package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type NotificationsCfg struct {
	Config   csplugin.PluginConfig  `json:"plugin_config"`
	Profiles []*csconfig.ProfileCfg `json:"associated_profiles"`
	ids      []uint
}

type cliNotifications struct{}

func NewCLINotifications() *cliNotifications {
	return &cliNotifications{}
}

func (cli cliNotifications) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "notifications [action]",
		Short:             "Helper for notification plugin configuration",
		Long:              "To list/inspect/test notification template",
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"notifications", "notification"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := require.LAPI(csConfig); err != nil {
				return err
			}
			if err := csConfig.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			if err := require.Notifications(csConfig); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewInspectCmd())
	cmd.AddCommand(cli.NewReinjectCmd())
	cmd.AddCommand(cli.NewTestCmd())

	return cmd
}

func getPluginConfigs() (map[string]csplugin.PluginConfig, error) {
	pcfgs := map[string]csplugin.PluginConfig{}
	wf := func(path string, info fs.FileInfo, err error) error {
		if info == nil {
			return fmt.Errorf("error while traversing directory %s: %w", path, err)
		}
		name := filepath.Join(csConfig.ConfigPaths.NotificationDir, info.Name()) //Avoid calling info.Name() twice
		if (strings.HasSuffix(name, "yaml") || strings.HasSuffix(name, "yml")) && !(info.IsDir()) {
			ts, err := csplugin.ParsePluginConfigFile(name)
			if err != nil {
				return fmt.Errorf("loading notifification plugin configuration with %s: %w", name, err)
			}
			for _, t := range ts {
				csplugin.SetRequiredFields(&t)
				pcfgs[t.Name] = t
			}
		}
		return nil
	}

	if err := filepath.Walk(csConfig.ConfigPaths.NotificationDir, wf); err != nil {
		return nil, fmt.Errorf("while loading notifification plugin configuration: %w", err)
	}
	return pcfgs, nil
}

func getProfilesConfigs() (map[string]NotificationsCfg, error) {
	// A bit of a tricky stuf now: reconcile profiles and notification plugins
	pcfgs, err := getPluginConfigs()
	if err != nil {
		return nil, err
	}
	ncfgs := map[string]NotificationsCfg{}
	for _, pc := range pcfgs {
		ncfgs[pc.Name] = NotificationsCfg{
			Config: pc,
		}
	}
	profiles, err := csprofiles.NewProfile(csConfig.API.Server.Profiles)
	if err != nil {
		return nil, fmt.Errorf("while extracting profiles from configuration: %w", err)
	}
	for profileID, profile := range profiles {
		for _, notif := range profile.Cfg.Notifications {
			pc, ok := pcfgs[notif]
			if !ok {
				return nil, fmt.Errorf("notification plugin '%s' does not exist", notif)
			}
			tmp, ok := ncfgs[pc.Name]
			if !ok {
				return nil, fmt.Errorf("notification plugin '%s' does not exist", pc.Name)
			}
			tmp.Profiles = append(tmp.Profiles, profile.Cfg)
			tmp.ids = append(tmp.ids, uint(profileID))
			ncfgs[pc.Name] = tmp
		}
	}
	return ncfgs, nil
}

func (cli cliNotifications) NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list active notifications plugins",
		Long:              `list active notifications plugins`,
		Example:           `cscli notifications list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			ncfgs, err := getProfilesConfigs()
			if err != nil {
				return fmt.Errorf("can't build profiles configuration: %w", err)
			}

			if csConfig.Cscli.Output == "human" {
				notificationListTable(color.Output, ncfgs)
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(ncfgs, "", " ")
				if err != nil {
					return fmt.Errorf("failed to marshal notification configuration: %w", err)
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"Name", "Type", "Profile name"})
				if err != nil {
					return fmt.Errorf("failed to write raw header: %w", err)
				}
				for _, b := range ncfgs {
					profilesList := []string{}
					for _, p := range b.Profiles {
						profilesList = append(profilesList, p.Name)
					}
					err := csvwriter.Write([]string{b.Config.Name, b.Config.Type, strings.Join(profilesList, ", ")})
					if err != nil {
						return fmt.Errorf("failed to write raw content: %w", err)
					}
				}
				csvwriter.Flush()
			}
			return nil
		},
	}

	return cmd
}

func (cli cliNotifications) NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "inspect",
		Short:             "Inspect active notifications plugin configuration",
		Long:              `Inspect active notifications plugin and show configuration`,
		Example:           `cscli notifications inspect <plugin_name>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if args[0] == "" {
				return fmt.Errorf("please provide a plugin name to inspect")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ncfgs, err := getProfilesConfigs()
			if err != nil {
				return fmt.Errorf("can't build profiles configuration: %w", err)
			}
			cfg, ok := ncfgs[args[0]]
			if !ok {
				return fmt.Errorf("plugin '%s' does not exist or is not active", args[0])
			}
			if csConfig.Cscli.Output == "human" || csConfig.Cscli.Output == "raw" {
				fmt.Printf(" - %15s: %15s\n", "Type", cfg.Config.Type)
				fmt.Printf(" - %15s: %15s\n", "Name", cfg.Config.Name)
				fmt.Printf(" - %15s: %15s\n", "Timeout", cfg.Config.TimeOut)
				fmt.Printf(" - %15s: %15s\n", "Format", cfg.Config.Format)
				for k, v := range cfg.Config.Config {
					fmt.Printf(" - %15s: %15v\n", k, v)
				}
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(cfg, "", " ")
				if err != nil {
					return fmt.Errorf("failed to marshal notification configuration: %w", err)
				}
				fmt.Printf("%s", string(x))
			}
			return nil
		},
	}

	return cmd
}

func (cli cliNotifications) NewTestCmd() *cobra.Command {
	var (
		pluginBroker  csplugin.PluginBroker
		pluginTomb    tomb.Tomb
		alertOverride string
	)
	cmd := &cobra.Command{
		Use:               "test [plugin name]",
		Short:             "send a generic test alert to notification plugin",
		Long:              `send a generic test alert to a notification plugin to test configuration even if is not active`,
		Example:           `cscli notifications test [plugin_name]`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			pconfigs, err := getPluginConfigs()
			if err != nil {
				return fmt.Errorf("can't build profiles configuration: %w", err)
			}
			cfg, ok := pconfigs[args[0]]
			if !ok {
				return fmt.Errorf("plugin name: '%s' does not exist", args[0])
			}
			//Create a single profile with plugin name as notification name
			return pluginBroker.Init(csConfig.PluginConfig, []*csconfig.ProfileCfg{
				{
					Notifications: []string{
						cfg.Name,
					},
				},
			}, csConfig.ConfigPaths)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			pluginTomb.Go(func() error {
				pluginBroker.Run(&pluginTomb)
				return nil
			})
			alert := &models.Alert{
				Capacity: ptr.Of(int32(0)),
				Decisions: []*models.Decision{{
					Duration: ptr.Of("4h"),
					Scope:    ptr.Of("Ip"),
					Value:    ptr.Of("10.10.10.10"),
					Type:     ptr.Of("ban"),
					Scenario: ptr.Of("test alert"),
					Origin:   ptr.Of(types.CscliOrigin),
				}},
				Events:          []*models.Event{},
				EventsCount:     ptr.Of(int32(1)),
				Leakspeed:       ptr.Of("0"),
				Message:         ptr.Of("test alert"),
				ScenarioHash:    ptr.Of(""),
				Scenario:        ptr.Of("test alert"),
				ScenarioVersion: ptr.Of(""),
				Simulated:       ptr.Of(false),
				Source: &models.Source{
					AsName:   "",
					AsNumber: "",
					Cn:       "",
					IP:       "10.10.10.10",
					Range:    "",
					Scope:    ptr.Of("Ip"),
					Value:    ptr.Of("10.10.10.10"),
				},
				StartAt:   ptr.Of(time.Now().UTC().Format(time.RFC3339)),
				StopAt:    ptr.Of(time.Now().UTC().Format(time.RFC3339)),
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}
			if err := yaml.Unmarshal([]byte(alertOverride), alert); err != nil {
				return fmt.Errorf("failed to unmarshal alert override: %w", err)
			}
			pluginBroker.PluginChannel <- csplugin.ProfileAlert{
				ProfileID: uint(0),
				Alert:     alert,
			}
			//time.Sleep(2 * time.Second) // There's no mechanism to ensure notification has been sent
			pluginTomb.Kill(fmt.Errorf("terminating"))
			pluginTomb.Wait()
			return nil
		},
	}
	cmd.Flags().StringVarP(&alertOverride, "alert", "a", "", "JSON string used to override alert fields in the generic alert (see crowdsec/pkg/models/alert.go in the source tree for the full definition of the object)")

	return cmd
}

func (cli cliNotifications) NewReinjectCmd() *cobra.Command {
	var alertOverride string
	var alert *models.Alert

	cmd := &cobra.Command{
		Use:   "reinject",
		Short: "reinject an alert into profiles to trigger notifications",
		Long:  `reinject an alert into profiles to be evaluated by the filter and sent to matched notifications plugins`,
		Example: `
cscli notifications reinject <alert_id>
cscli notifications reinject <alert_id> -a '{"remediation": false,"scenario":"notification/test"}'
cscli notifications reinject <alert_id> -a '{"remediation": true,"scenario":"notification/test"}'
`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			alert, err = FetchAlertFromArgString(args[0])
			if err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				pluginBroker csplugin.PluginBroker
				pluginTomb   tomb.Tomb
			)
			if alertOverride != "" {
				if err := json.Unmarshal([]byte(alertOverride), alert); err != nil {
					return fmt.Errorf("can't unmarshal data in the alert flag: %w", err)
				}
			}
			err := pluginBroker.Init(csConfig.PluginConfig, csConfig.API.Server.Profiles, csConfig.ConfigPaths)
			if err != nil {
				return fmt.Errorf("can't initialize plugins: %w", err)
			}

			pluginTomb.Go(func() error {
				pluginBroker.Run(&pluginTomb)
				return nil
			})

			profiles, err := csprofiles.NewProfile(csConfig.API.Server.Profiles)
			if err != nil {
				return fmt.Errorf("cannot extract profiles from configuration: %w", err)
			}

			for id, profile := range profiles {
				_, matched, err := profile.EvaluateProfile(alert)
				if err != nil {
					return fmt.Errorf("can't evaluate profile %s: %w", profile.Cfg.Name, err)
				}
				if !matched {
					log.Infof("The profile %s didn't match", profile.Cfg.Name)
					continue
				}
				log.Infof("The profile %s matched, sending to its configured notification plugins", profile.Cfg.Name)
			loop:
				for {
					select {
					case pluginBroker.PluginChannel <- csplugin.ProfileAlert{
						ProfileID: uint(id),
						Alert:     alert,
					}:
						break loop
					default:
						time.Sleep(50 * time.Millisecond)
						log.Info("sleeping\n")

					}
				}
				if profile.Cfg.OnSuccess == "break" {
					log.Infof("The profile %s contains a 'on_success: break' so bailing out", profile.Cfg.Name)
					break
				}
			}
			//time.Sleep(2 * time.Second) // There's no mechanism to ensure notification has been sent
			pluginTomb.Kill(fmt.Errorf("terminating"))
			pluginTomb.Wait()
			return nil
		},
	}
	cmd.Flags().StringVarP(&alertOverride, "alert", "a", "", "JSON string used to override alert fields in the reinjected alert (see crowdsec/pkg/models/alert.go in the source tree for the full definition of the object)")

	return cmd
}

func FetchAlertFromArgString(toParse string) (*models.Alert, error) {
	id, err := strconv.Atoi(toParse)
	if err != nil {
		return nil, fmt.Errorf("bad alert id %s", toParse)
	}
	apiURL, err := url.Parse(csConfig.API.Client.Credentials.URL)
	if err != nil {
		return nil, fmt.Errorf("error parsing the URL of the API: %w", err)
	}
	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:     csConfig.API.Client.Credentials.Login,
		Password:      strfmt.Password(csConfig.API.Client.Credentials.Password),
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	if err != nil {
		return nil, fmt.Errorf("error creating the client for the API: %w", err)
	}
	alert, _, err := client.Alerts.GetByID(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("can't find alert with id %d: %w", id, err)
	}
	return alert, nil
}
