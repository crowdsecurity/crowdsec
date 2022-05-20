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

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"
)

type NotificationsCfg struct {
	Config   csplugin.PluginConfig  `json:"plugin_config"`
	Profiles []*csconfig.ProfileCfg `json:"associated_profiles"`
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
				log.Fatalf(err.Error())
			}
		},
	}

	var cmdNotificationsList = &cobra.Command{
		Use:               "list",
		Short:             "List active notifications plugins",
		Long:              `List active notifications plugins`,
		Example:           `cscli notifications list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, arg []string) {
			ncfgs := getNotificationsConfiguration()
			if csConfig.Cscli.Output == "human" {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Name", "Type", "Profile name"})
				for _, b := range ncfgs {
					profilesList := []string{}
					for _, p := range b.Profiles {
						profilesList = append(profilesList, p.Name)
					}
					table.Append([]string{b.Config.Name, b.Config.Type, strings.Join(profilesList, ", ")})
				}
				table.Render()

			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(ncfgs, "", " ")
				if err != nil {
					log.Fatalf("failed to marshal notification configuration")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"Name", "Type", "Profile name"})
				if err != nil {
					log.Fatalf("failed to write raw header: %s", err)
				}
				for _, b := range ncfgs {
					profilesList := []string{}
					for _, p := range b.Profiles {
						profilesList = append(profilesList, p.Name)
					}
					err := csvwriter.Write([]string{b.Config.Name, b.Config.Type, strings.Join(profilesList, ", ")})
					if err != nil {
						log.Fatalf("failed to write raw content: %s", err)
					}
				}
				csvwriter.Flush()
			}
		},
	}
	cmdNotifications.AddCommand(cmdNotificationsList)

	var cmdNotificationsInspect = &cobra.Command{
		Use:               "inspect",
		Short:             "Inspect active notifications plugin configuration",
		Long:              `Inspect active notifications plugin and show configuration`,
		Example:           `cscli notifications inspect <plugin_name>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, arg []string) {
			var (
				cfg NotificationsCfg
				ok  bool
			)

			pluginName := arg[0]

			if pluginName == "" {
				log.Fatalf("Please provide a plugin name to inspect")
			}
			ncfgs := getNotificationsConfiguration()
			if cfg, ok = ncfgs[pluginName]; !ok {
				log.Fatalf("The provided plugin name doesn't exist or isn't active")
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
					log.Fatalf("failed to marshal notification configuration")
				}
				fmt.Printf("%s", string(x))
			}
		},
	}
	cmdNotifications.AddCommand(cmdNotificationsInspect)
	var cmdNotificationsReinject = &cobra.Command{
		Use:               "reinject",
		Short:             "reinject alerts into notifications system",
		Long:              `Reinject alerts into notifications system`,
		Example:           `cscli notifications reinject <alert_id> <plugin_name>`,
		Args:              cobra.ExactArgs(2),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var (
				pluginBroker csplugin.PluginBroker
				pluginTomb   tomb.Tomb
			)
			if len(args) != 2 {
				printHelp(cmd)
				return
			}
			id, err := strconv.Atoi(args[0])
			if err != nil {
				log.Fatalf("bad alert id %s", args[0])
			}
			if err := csConfig.LoadAPIClient(); err != nil {
				log.Fatalf("loading api client: %s", err.Error())
			}
			if csConfig.API.Client == nil {
				log.Fatalln("There is no configuration on 'api_client:'")
			}
			if csConfig.API.Client.Credentials == nil {
				log.Fatalf("Please provide credentials for the API in '%s'", csConfig.API.Client.CredentialsFilePath)
			}
			apiURL, err := url.Parse(csConfig.API.Client.Credentials.URL)
			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      strfmt.Password(csConfig.API.Client.Credentials.Password),
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v1",
			})

			alert, _, err := Client.Alerts.GetByID(context.Background(), id)
			if err != nil {
				log.Fatalf("can't find alert with id %s: %s", args[0], err)

			}

			err = pluginBroker.Init(csConfig.PluginConfig, csConfig.API.Server.Profiles, csConfig.ConfigPaths)
			if err != nil {
				log.Fatalf("Can't initialize plugins: %s", err.Error())
			}

			pluginTomb.Go(func() error {
				pluginBroker.Run(&pluginTomb)
				fmt.Printf("\nreturned\n")
				return nil
			})

		loop:
			for {
				select {
				case pluginBroker.PluginChannel <- csplugin.ProfileAlert{
					ProfileID: 1,
					Alert:     alert,
				}:
					break loop
				default:
					time.Sleep(50 * time.Millisecond)
					log.Info("sleeping\n")

				}
			}
			pluginTomb.Kill(errors.New("terminating"))
			pluginTomb.Wait()

		},
	}
	cmdNotifications.AddCommand(cmdNotificationsReinject)
	return cmdNotifications
}

func getNotificationsConfiguration() map[string]NotificationsCfg {
	pcfgs := map[string]csplugin.PluginConfig{}
	wf := func(path string, info fs.FileInfo, err error) error {
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
		log.Fatalf("Loading notifification plugin configuration: %s", err)
	}

	// A bit of a tricky stuf now: reconcile profiles and notification plugins
	ncfgs := map[string]NotificationsCfg{}
	for _, profile := range csConfig.API.Server.Profiles {
	loop:
		for _, notif := range profile.Notifications {
			for name, pc := range pcfgs {
				if notif == name {
					if _, ok := ncfgs[pc.Name]; !ok {
						ncfgs[pc.Name] = NotificationsCfg{
							Config:   pc,
							Profiles: []*csconfig.ProfileCfg{profile},
						}
						continue loop
					}
					tmp := ncfgs[pc.Name]
					for _, pr := range tmp.Profiles {
						var profiles []*csconfig.ProfileCfg
						if pr.Name == profile.Name {
							continue
						}
						profiles = append(tmp.Profiles, profile)
						ncfgs[pc.Name] = NotificationsCfg{
							Config:   tmp.Config,
							Profiles: profiles,
						}
					}
				}
			}
		}
	}
	return ncfgs
}
