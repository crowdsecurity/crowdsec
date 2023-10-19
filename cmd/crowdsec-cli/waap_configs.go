package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewWaapConfigsCmd() *cobra.Command {
	cmdWaapConfigs := &cobra.Command{
		Use:   "waap-configs <action> [waap-config]...",
		Short: "Manage hub waap configs",
		Example: `cscli waap-configs list -a
cscli waap-configs install crowdsecurity/crs
cscli waap-configs inspect crowdsecurity/crs
cscli waap-configs upgrade crowdsecurity/crs
cscli waap-configs remove crowdsecurity/crs
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"waap-config"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := require.Hub(csConfig); err != nil {
				return err
			}

			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof(ReloadMessage())
		},
	}

	cmdWaapConfigs.AddCommand(NewCmdWaapConfigsInstall())
	cmdWaapConfigs.AddCommand(NewCmdWaapConfigsRemove())
	cmdWaapConfigs.AddCommand(NewCmdWaapConfigsUpgrade())
	cmdWaapConfigs.AddCommand(NewCmdWaapConfigsInspect())
	cmdWaapConfigs.AddCommand(NewCmdWaapConfigsList())

	return cmdWaapConfigs
}

func runWaapConfigsInstall(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	downloadOnly, err := flags.GetBool("download-only")
	if err != nil {
		return err
	}

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	ignoreError, err := flags.GetBool("ignore")
	if err != nil {
		return err
	}

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	for _, name := range args {
		t := hub.GetItem(cwhub.WAAP_CONFIGS, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.WAAP_CONFIGS, name)
			Suggest(cwhub.WAAP_CONFIGS, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := hub.InstallItem(name, cwhub.WAAP_CONFIGS, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewCmdWaapConfigsInstall() *cobra.Command {
	cmdWaapConfigsInstall := &cobra.Command{
		Use:               "install <waap-config>...",
		Short:             "Install given waap config(s)",
		Long:              `Fetch and install one or more waap configs from the hub`,
		Example:           `cscli waap-configs install crowdsecurity/vpatch`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.WAAP_CONFIGS, args, toComplete)
		},
		RunE: runWaapConfigsInstall,
	}

	flags := cmdWaapConfigsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple waap rules")

	return cmdWaapConfigsInstall
}

func runWaapConfigsRemove(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	purge, err := flags.GetBool("purge")
	if err != nil {
		return err
	}

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	if all {
		err := hub.RemoveMany(cwhub.WAAP_CONFIGS, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one waap rule to remove or '--all'")
	}

	for _, name := range args {
		err := hub.RemoveMany(cwhub.WAAP_CONFIGS, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapConfigsRemove() *cobra.Command {
	cmdWaapConfigsRemove := &cobra.Command{
		Use:               "remove <waap-config>...",
		Short:             "Remove given waap config(s)",
		Long:              `remove one or more waap configs`,
		Example:           `cscli waap-configs remove crowdsecurity/vpatch`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_CONFIGS, args, toComplete)
		},
		RunE: runWaapConfigsRemove,
	}

	flags := cmdWaapConfigsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the waap configs")

	return cmdWaapConfigsRemove
}

func runWaapConfigsUpgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	if all {
		if err := hub.UpgradeConfig(cwhub.WAAP_CONFIGS, "", force); err != nil {
			return err
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one waap config to upgrade or '--all'")
	}

	for _, name := range args {
		if err := hub.UpgradeConfig(cwhub.WAAP_CONFIGS, name, force); err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapConfigsUpgrade() *cobra.Command {
	cmdWaapConfigsUpgrade := &cobra.Command{
		Use:               "upgrade <waap-config>...",
		Short:             "Upgrade given waap config(s)",
		Long:              `Fetch and upgrade one or more waap configs from the hub`,
		Example:           `cscli waap-configs upgrade crowdsecurity/crs`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_CONFIGS, args, toComplete)
		},
		RunE: runWaapConfigsUpgrade,
	}

	flags := cmdWaapConfigsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the waap configs")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdWaapConfigsUpgrade
}

func runWaapConfigsInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	url, err := flags.GetString("url")
	if err != nil {
		return err
	}

	if url != "" {
		csConfig.Cscli.PrometheusUrl = url
	}

	noMetrics, err := flags.GetBool("no-metrics")
	if err != nil {
		return err
	}

	for _, name := range args {
		if err = InspectItem(name, cwhub.WAAP_CONFIGS, noMetrics); err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapConfigsInspect() *cobra.Command {
	cmdWaapConfigsInspect := &cobra.Command{
		Use:               "inspect <waap-config>",
		Short:             "Inspect a waap config",
		Long:              `Inspect a waap config`,
		Example:           `cscli waap-configs inspect crowdsecurity/vpatch`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_CONFIGS, args, toComplete)
		},
		RunE: runWaapConfigsInspect,
	}

	flags := cmdWaapConfigsInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdWaapConfigsInspect
}

func runWaapConfigsList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	if err = ListItems(color.Output, []string{cwhub.WAAP_CONFIGS}, args, false, true, all); err != nil {
		return err
	}

	return nil
}

func NewCmdWaapConfigsList() *cobra.Command {
	cmdWaapConfigsList := &cobra.Command{
		Use:   "list [waap-config]...",
		Short: "List waap configs",
		Long:  `List of installed/available/specified waap configs`,
		Example: `cscli waap-configs list
cscli waap-configs list -a
cscli waap-configs list crowdsecurity/crs`,
		DisableAutoGenTag: true,
		RunE:              runWaapConfigsList,
	}

	flags := cmdWaapConfigsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdWaapConfigsList
}
