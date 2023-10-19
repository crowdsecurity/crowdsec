package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewPostOverflowsCmd() *cobra.Command {
	cmdPostOverflows := &cobra.Command{
		Use:   "postoverflows <action> [postoverflow]...",
		Short: "Manage hub postoverflows",
		Example: `cscli postoverflows list -a
cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns
cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"postoverflow"},
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

	cmdPostOverflows.AddCommand(NewPostOverflowsInstallCmd())
	cmdPostOverflows.AddCommand(NewPostOverflowsRemoveCmd())
	cmdPostOverflows.AddCommand(NewPostOverflowsUpgradeCmd())
	cmdPostOverflows.AddCommand(NewPostOverflowsInspectCmd())
	cmdPostOverflows.AddCommand(NewPostOverflowsListCmd())

	return cmdPostOverflows
}

func runPostOverflowsInstall(cmd *cobra.Command, args []string) error {
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
		t := hub.GetItem(cwhub.POSTOVERFLOWS, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.POSTOVERFLOWS, name)
			Suggest(cwhub.POSTOVERFLOWS, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := hub.InstallItem(name, cwhub.POSTOVERFLOWS, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewPostOverflowsInstallCmd() *cobra.Command {
	cmdPostOverflowsInstall := &cobra.Command{
		Use:               "install <postoverflow>...",
		Short:             "Install given postoverflow(s)",
		Long:              `Fetch and install one or more postoverflows from the hub`,
		Example:           `cscli postoverflows install crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.POSTOVERFLOWS, args, toComplete)
		},
		RunE: runPostOverflowsInstall,
	}

	flags := cmdPostOverflowsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple postoverflows")

	return cmdPostOverflowsInstall
}

func runPostOverflowsRemove(cmd *cobra.Command, args []string) error {
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
		err := hub.RemoveMany(cwhub.POSTOVERFLOWS, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one postoverflow to remove or '--all'")
	}

	for _, name := range args {
		err := hub.RemoveMany(cwhub.POSTOVERFLOWS, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewPostOverflowsRemoveCmd() *cobra.Command {
	cmdPostOverflowsRemove := &cobra.Command{
		Use:               "remove <postoverflow>...",
		Short:             "Remove given postoverflow(s)",
		Long:              `remove one or more postoverflows from the hub`,
		Example:           `cscli postoverflows remove crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.POSTOVERFLOWS, args, toComplete)
		},
		RunE: runPostOverflowsRemove,
	}

	flags := cmdPostOverflowsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Delete all the postoverflows")

	return cmdPostOverflowsRemove
}

func runPostOverflowUpgrade(cmd *cobra.Command, args []string) error {
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
		if err := hub.UpgradeConfig(cwhub.POSTOVERFLOWS, "", force); err != nil {
			return err
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one postoverflow to upgrade or '--all'")
	}

	for _, name := range args {
		if err := hub.UpgradeConfig(cwhub.POSTOVERFLOWS, name, force); err != nil {
			return err
		}
	}

	return nil
}

func NewPostOverflowsUpgradeCmd() *cobra.Command {
	cmdPostOverflowsUpgrade := &cobra.Command{
		Use:               "upgrade <postoverflow>...",
		Short:             "Upgrade given postoverflow(s)",
		Long:              `Fetch and upgrade one or more postoverflows from the hub`,
		Example:           `cscli postoverflows upgrade crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.POSTOVERFLOWS, args, toComplete)
		},
		RunE: runPostOverflowUpgrade,
	}

	flags := cmdPostOverflowsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the postoverflows")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdPostOverflowsUpgrade
}

func runPostOverflowsInspect(cmd *cobra.Command, args []string) error {
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
		if err = InspectItem(name, cwhub.POSTOVERFLOWS, noMetrics); err != nil {
			return err
		}
	}

	return nil
}

func NewPostOverflowsInspectCmd() *cobra.Command {
	cmdPostOverflowsInspect := &cobra.Command{
		Use:               "inspect <postoverflow>",
		Short:             "Inspect a postoverflow",
		Long:              `Inspect a postoverflow`,
		Example:           `cscli postoverflows inspect crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.POSTOVERFLOWS, args, toComplete)
		},
		RunE: runPostOverflowsInspect,
	}

	flags := cmdPostOverflowsInspect.Flags()

	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdPostOverflowsInspect
}

func runPostOverflowsList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	if err = ListItems(color.Output, []string{cwhub.POSTOVERFLOWS}, args, false, true, all); err != nil {
		return err
	}

	return nil
}

func NewPostOverflowsListCmd() *cobra.Command {
	cmdPostOverflowsList := &cobra.Command{
		Use:   "list [postoverflow]...",
		Short: "List postoverflows",
		Long:  `List of installed/available/specified postoverflows`,
		Example: `cscli postoverflows list
cscli postoverflows list -a
cscli postoverflows list crowdsecurity/cdn-whitelist crowdsecurity/rdns`,
		DisableAutoGenTag: true,
		RunE:              runPostOverflowsList,
	}

	flags := cmdPostOverflowsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdPostOverflowsList
}
