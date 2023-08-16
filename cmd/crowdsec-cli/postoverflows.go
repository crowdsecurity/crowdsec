package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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
		cscli postoverflows remove crowdsecurity/cdn-whitelist`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"postoverflow"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadHub(); err != nil {
				return err
			}
			if csConfig.Hub == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := cwhub.SetHubBranch(); err != nil {
				return fmt.Errorf("while setting hub branch: %w", err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Info("Run 'sudo cscli hub update' to get the hub index")
				return fmt.Errorf("failed to get hub index: %w", err)
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

func NewPostOverflowsInstallCmd() *cobra.Command {
	var ignoreError bool

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
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.PARSERS_OVFLW, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.PARSERS_OVFLW, name)
					Suggest(cwhub.PARSERS_OVFLW, name, nearestItem.Name, score, ignoreError)
					continue
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS_OVFLW, forceAction, downloadOnly); err != nil {
					if !ignoreError {
						return fmt.Errorf("error while installing '%s': %w", name, err)
					}
					log.Errorf("Error while installing '%s': %s", name, err)
				}
			}
			return nil
		},
	}

	cmdPostOverflowsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowsInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflowsInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple postoverflows")

	return cmdPostOverflowsInstall
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, "", all, purge, forceAction)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("specify at least one postoverflow to remove or '--all'")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, name, all, purge, forceAction)
			}

			return nil
		},
	}

	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the postoverflows")

	return cmdPostOverflowsRemove
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, "", forceAction)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one postoverflow to upgrade or '--all'")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, name, forceAction)
				}
			}
			return nil
		},
	}

	cmdPostOverflowsUpgrade.PersistentFlags().BoolVarP(&all, "all", "a", false, "Upgrade all the postoverflows")
	cmdPostOverflowsUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdPostOverflowsUpgrade
}

func NewPostOverflowsInspectCmd() *cobra.Command {
	cmdPostOverflowsInspect := &cobra.Command{
		Use:               "inspect [config]",
		Short:             "Inspect given postoverflow",
		Long:              `Inspect given postoverflow`,
		Example:           `cscli postoverflows inspect crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			InspectItem(args[0], cwhub.PARSERS_OVFLW)
		},
	}

	return cmdPostOverflowsInspect
}

func NewPostOverflowsListCmd() *cobra.Command {
	cmdPostOverflowsList := &cobra.Command{
		Use:   "list [config]",
		Short: "List all postoverflows or given one",
		Long:  `List all postoverflows or given one`,
		Example: `cscli postoverflows list
cscli postoverflows list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems(color.Output, []string{cwhub.PARSERS_OVFLW}, args, false, true, all)
		},
	}

	cmdPostOverflowsList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmdPostOverflowsList
}
