package main

import (
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
			if _, err := require.Hub(csConfig, require.RemoteHub(csConfig)); err != nil {
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
		RunE: itemsInstallRunner(hubItemTypes[cwhub.WAAP_CONFIGS]),
	}

	flags := cmdWaapConfigsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple waap rules")

	return cmdWaapConfigsInstall
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
		RunE: itemsRemoveRunner(hubItemTypes[cwhub.WAAP_CONFIGS]),
	}

	flags := cmdWaapConfigsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the waap configs")

	return cmdWaapConfigsRemove
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
		RunE: itemsUpgradeRunner(hubItemTypes[cwhub.WAAP_CONFIGS]),
	}

	flags := cmdWaapConfigsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the waap configs")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdWaapConfigsUpgrade
}

func NewCmdWaapConfigsInspect() *cobra.Command {
	//FIXME: we need to show the "compiled" rules
	it := hubItemTypes[cwhub.WAAP_CONFIGS]
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
		RunE: itemsInspectRunner(it),
	}

	flags := cmdWaapConfigsInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdWaapConfigsInspect
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
		RunE:              itemsListRunner(hubItemTypes[cwhub.WAAP_CONFIGS]),
	}

	flags := cmdWaapConfigsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdWaapConfigsList
}
