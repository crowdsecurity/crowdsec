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
		Use:   "postoverflows [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect postoverflow(s) from hub",
		Example: `cscli postoverflows install crowdsecurity/cdn-whitelist
cscli postoverflows inspect crowdsecurity/cdn-whitelist
cscli postoverflows upgrade crowdsecurity/cdn-whitelist
cscli postoverflows list
cscli postoverflows remove crowdsecurity/cdn-whitelist
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"postoverflow"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := require.Hub(csConfig); err != nil {
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

	for _, name := range args {
		t := cwhub.GetItem(cwhub.PARSERS_OVFLW, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.PARSERS_OVFLW, name)
			Suggest(cwhub.PARSERS_OVFLW, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS_OVFLW, force, downloadOnly); err != nil {
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
		Use:               "install [config]",
		Short:             "Install given postoverflow(s)",
		Long:              `Fetch and install given postoverflow(s) from hub`,
		Example:           `cscli postoverflows install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		RunE: runPostOverflowsInstall,
	}

	flags := cmdPostOverflowsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install : Overwrite tainted and outdated files")
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

	if all {
		err := cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one postoverflow to remove or '--all'")
	}

	for _, name := range args {
		err := cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewPostOverflowsRemoveCmd() *cobra.Command {
	cmdPostOverflowsRemove := &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given postoverflow(s)",
		Long:              `remove given postoverflow(s)`,
		Example:           `cscli postoverflows remove crowdsec/xxx crowdsec/xyz`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		RunE: runPostOverflowsRemove,
	}

	flags := cmdPostOverflowsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove : Remove tainted and outdated files")
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

	if all {
		cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, "", force)
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one postoverflow to upgrade or '--all'")
	}

	for _, name := range args {
		cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, name, force)
	}

	return nil
}

func NewPostOverflowsUpgradeCmd() *cobra.Command {
	cmdPostOverflowsUpgrade := &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given postoverflow(s)",
		Long:              `Fetch and Upgrade given postoverflow(s) from hub`,
		Example:           `cscli postoverflows upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		RunE: runPostOverflowUpgrade,
	}

	flags := cmdPostOverflowsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the postoverflows")
	flags.Bool("force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdPostOverflowsUpgrade
}

func runPostOverflowsInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	var err error
	// XXX: set global
	prometheusURL, err = flags.GetString("url")
	if err != nil {
		return err
	}

	InspectItem(args[0], cwhub.PARSERS_OVFLW)

	return nil
}

func NewPostOverflowsInspectCmd() *cobra.Command {
	cmdPostOverflowsInspect := &cobra.Command{
		Use:               "inspect [config]",
		Short:             "Inspect given postoverflow",
		Long:              `Inspect given postoverflow`,
		Example:           `cscli postoverflows inspect crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		RunE: runPostOverflowsInspect,
	}

	flags := cmdPostOverflowsInspect.Flags()
	// XXX: is this needed for postoverflows?
	flags.StringP("url", "u", "", "Prometheus url")

	return cmdPostOverflowsInspect
}

func runPostOverflowsList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	// XXX: will happily ignore missing postoverflows
	ListItems(color.Output, []string{cwhub.PARSERS_OVFLW}, args, false, true, all)

	return nil
}

func NewPostOverflowsListCmd() *cobra.Command {
	cmdPostOverflowsList := &cobra.Command{
		Use:   "list [config]",
		Short: "List all postoverflows or given one",
		Long:  `List all postoverflows or given one`,
		Example: `cscli postoverflows list
cscli postoverflows list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		RunE:              runPostOverflowsList,
	}

	flags := cmdPostOverflowsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdPostOverflowsList
}
