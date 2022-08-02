package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
			if csConfig.ConfigPaths.NotificationDir == "" {
				log.Fatalf("config_paths.notification_dir is not set in crowdsec config")
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
	return cmdNotifications
}

func getNotificationsConfiguration() map[string]NotificationsCfg {
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
