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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/csprofiles"
)


type NotificationsCfg struct {
	Config   csplugin.PluginConfig  `json:"plugin_config"`
	Profiles []*csconfig.ProfileCfg `json:"associated_profiles"`
	ids      []uint
}


func NewNotificationsCmd() *cobra.Command {
	var cmdNotifications = &cobra.Command{
		Use:               "notifications [action]",
		Short:             "Helper for notification plugin configuration",
		Long:              "To list/inspect/test notification template",
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"notifications", "notification"},
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var (
				err error
			)
			if err = csConfig.API.Server.LoadProfiles(); err != nil {
				log.Fatal(err)
			}
			if csConfig.ConfigPaths.NotificationDir == "" {
				log.Fatalf("config_paths.notification_dir is not set in crowdsec config")
			}
		},
	}


	cmdNotifications.AddCommand(NewNotificationsListCmd())
	cmdNotifications.AddCommand(NewNotificationsInspectCmd())
	cmdNotifications.AddCommand(NewNotificationsReinjectCmd())

	return cmdNotifications
}


func getNotificationsConfiguration() (map[string]NotificationsCfg, error) {
	pcfgs := map[string]csplugin.PluginConfig{}
	wf := func(path string, info fs.FileInfo, err error) error {
		if info == nil {
			return errors.Wrapf(err, "error while traversing directory %s", path)
		}
		name := filepath.Join(csConfig.ConfigPaths.NotificationDir, info.Name()) //Avoid calling info.Name() twice
		if (strings.HasSuffix(name, "yaml") || strings.HasSuffix(name, "yml")) && !(info.IsDir()) {
			ts, err := csplugin.ParsePluginConfigFile(name)
			if err != nil {
				return errors.Wrapf(err, "Loading notifification plugin configuration with %s", name)
			}
			for _, t := range ts {
				pcfgs[t.Name] = t
			}
		}
		return nil
	}

	if err := filepath.Walk(csConfig.ConfigPaths.NotificationDir, wf); err != nil {
		return nil, errors.Wrap(err, "Loading notifification plugin configuration")
	}

	// A bit of a tricky stuf now: reconcile profiles and notification plugins
	ncfgs := map[string]NotificationsCfg{}
	profiles, err := csprofiles.NewProfile(csConfig.API.Server.Profiles)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot extract profiles from configuration")
	}
	for profileID, profile := range profiles {
	loop:
		for _, notif := range profile.Cfg.Notifications {
			for name, pc := range pcfgs {
				if notif == name {
					if _, ok := ncfgs[pc.Name]; !ok {
						ncfgs[pc.Name] = NotificationsCfg{
							Config:   pc,
							Profiles: []*csconfig.ProfileCfg{profile.Cfg},
							ids:      []uint{uint(profileID)},
						}
						continue loop
					}
					tmp := ncfgs[pc.Name]
					for _, pr := range tmp.Profiles {
						var profiles []*csconfig.ProfileCfg
						if pr.Name == profile.Cfg.Name {
							continue
						}
						profiles = append(tmp.Profiles, profile.Cfg)
						ids := append(tmp.ids, uint(profileID))
						ncfgs[pc.Name] = NotificationsCfg{
							Config:   tmp.Config,
							Profiles: profiles,
							ids:      ids,
						}
					}
				}
			}
		}
	}
	return ncfgs, nil
}


func NewNotificationsListCmd() *cobra.Command {
	var cmdNotificationsList = &cobra.Command{
		Use:               "list",
		Short:             "List active notifications plugins",
		Long:              `List active notifications plugins`,
		Example:           `cscli notifications list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			ncfgs, err := getNotificationsConfiguration()
			if err != nil {
				return errors.Wrap(err, "Can't build profiles configuration")
			}

			if csConfig.Cscli.Output == "human" {
				notificationListTable(color.Output, ncfgs)
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(ncfgs, "", " ")
				if err != nil {
					return errors.New("failed to marshal notification configuration")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"Name", "Type", "Profile name"})
				if err != nil {
					return errors.Wrap(err, "failed to write raw header")
				}
				for _, b := range ncfgs {
					profilesList := []string{}
					for _, p := range b.Profiles {
						profilesList = append(profilesList, p.Name)
					}
					err := csvwriter.Write([]string{b.Config.Name, b.Config.Type, strings.Join(profilesList, ", ")})
					if err != nil {
						return errors.Wrap(err, "failed to write raw content")
					}
				}
				csvwriter.Flush()
			}
			return nil
		},
	}

	return cmdNotificationsList
}


func NewNotificationsInspectCmd() *cobra.Command {
	var cmdNotificationsInspect = &cobra.Command{
		Use:               "inspect",
		Short:             "Inspect active notifications plugin configuration",
		Long:              `Inspect active notifications plugin and show configuration`,
		Example:           `cscli notifications inspect <plugin_name>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			var (
				cfg NotificationsCfg
				ok  bool
			)

			pluginName := arg[0]

			if pluginName == "" {
				errors.New("Please provide a plugin name to inspect")
			}
			ncfgs, err := getNotificationsConfiguration()
			if err != nil {
				return errors.Wrap(err, "Can't build profiles configuration")
			}
			if cfg, ok = ncfgs[pluginName]; !ok {
				return errors.New("The provided plugin name doesn't exist or isn't active")
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
					return errors.New("failed to marshal notification configuration")
				}
				fmt.Printf("%s", string(x))
			}
			return nil
		},
	}

	return cmdNotificationsInspect
}


func NewNotificationsReinjectCmd() *cobra.Command {
	var remediation bool
	var alertOverride string

	var cmdNotificationsReinject = &cobra.Command{
		Use:   "reinject",
		Short: "reinject alert into notifications system",
		Long:  `Reinject alert into notifications system`,
		Example: `
cscli notifications reinject <alert_id>
cscli notifications reinject <alert_id> --remediation
cscli notifications reinject <alert_id> -a '{"remediation": true,"scenario":"notification/test"}'
`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				pluginBroker csplugin.PluginBroker
				pluginTomb   tomb.Tomb
			)
			if len(args) != 1 {
				printHelp(cmd)
				return errors.New("Wrong number of argument: there should be one argument")
			}

			//first: get the alert
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.New(fmt.Sprintf("bad alert id %s", args[0]))
			}
			if err := csConfig.LoadAPIClient(); err != nil {
				return errors.Wrapf(err, "loading api client")
			}
			if csConfig.API.Client == nil {
				return errors.New("There is no configuration on 'api_client:'")
			}
			if csConfig.API.Client.Credentials == nil {
				return errors.New(fmt.Sprintf("Please provide credentials for the API in '%s'", csConfig.API.Client.CredentialsFilePath))
			}
			apiURL, err := url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				return errors.Wrapf(err, "error parsing the URL of the API")
			}
			client, err := apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      strfmt.Password(csConfig.API.Client.Credentials.Password),
				UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
				URL:           apiURL,
				VersionPrefix: "v1",
			})
			if err != nil {
				return errors.Wrapf(err, "error creating the client for the API")
			}
			alert, _, err := client.Alerts.GetByID(context.Background(), id)
			if err != nil {
				return errors.Wrapf(err, fmt.Sprintf("can't find alert with id %s", args[0]))
			}

			if alertOverride != "" {
				if err = json.Unmarshal([]byte(alertOverride), alert); err != nil {
					return errors.Wrapf(err, "Can't unmarshal the data given in the alert flag")
				}
			}
			if !remediation {
				alert.Remediation = true
			}

			// second we start plugins
			err = pluginBroker.Init(csConfig.PluginConfig, csConfig.API.Server.Profiles, csConfig.ConfigPaths)
			if err != nil {
				return errors.Wrapf(err, "Can't initialize plugins")
			}

			pluginTomb.Go(func() error {
				pluginBroker.Run(&pluginTomb)
				return nil
			})

			//third: get the profile(s), and process the whole stuff

			profiles, err := csprofiles.NewProfile(csConfig.API.Server.Profiles)
			if err != nil {
				return errors.Wrap(err, "Cannot extract profiles from configuration")
			}

			for id, profile := range profiles {
				_, matched, err := profile.EvaluateProfile(alert)
				if err != nil {
					return errors.Wrapf(err, "can't evaluate profile %s", profile.Cfg.Name)
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

			//			time.Sleep(2 * time.Second) // There's no mechanism to ensure notification has been sent
			pluginTomb.Kill(errors.New("terminating"))
			pluginTomb.Wait()
			return nil
		},
	}
	cmdNotificationsReinject.Flags().BoolVarP(&remediation, "remediation", "r", false, "Set Alert.Remediation to false in the reinjected alert (see your profile filter configuration)")
	cmdNotificationsReinject.Flags().StringVarP(&alertOverride, "alert", "a", "", "JSON string used to override alert fields in the reinjected alert (see crowdsec/pkg/models/alert.go in the source tree for the full definition of the object)")

	return cmdNotificationsReinject
}
