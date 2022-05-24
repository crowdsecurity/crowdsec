package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewPostOverflowsCmd() *cobra.Command {
	var cmdPostOverflows = &cobra.Command{
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
				log.Fatalf(err.Error())
			}
			if csConfig.Hub == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := cwhub.SetHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
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

	var ignoreError bool
	var cmdPostOverflowsInstall = &cobra.Command{
		Use:               "install [config]",
		Short:             "Install given postoverflow(s)",
		Long:              `Fetch and install given postoverflow(s) from hub`,
		Example:           `cscli postoverflows install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range args {
				if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS_OVFLW, forceAction, downloadOnly); err != nil {
					if ignoreError {
						log.Errorf("Error while installing '%s': %s", name, err)
					} else {
						log.Fatalf("Error while installing '%s': %s", name, err)
					}
				}
			}
		},
	}
	cmdPostOverflowsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowsInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflowsInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple postoverflows")
	cmdPostOverflows.AddCommand(cmdPostOverflowsInstall)

	var cmdPostOverflowsRemove = &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given postoverflow(s)",
		Long:              `remove given postoverflow(s)`,
		Example:           `cscli postoverflows remove crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		Aliases:           []string{"delete"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, "", all, purge, forceAction)
				return
			}

			if len(args) == 0 {
				log.Fatalf("Specify at least one postoverflow to remove or '--all' flag.")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS_OVFLW, name, all, purge, forceAction)
			}
		},
	}
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the postoverflows")
	cmdPostOverflows.AddCommand(cmdPostOverflowsRemove)

	var cmdPostOverflowsUpgrade = &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given postoverflow(s)",
		Long:              `Fetch and Upgrade given postoverflow(s) from hub`,
		Example:           `cscli postoverflows upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, "", forceAction)
			} else {
				if len(args) == 0 {
					log.Fatalf("no target postoverflow to upgrade")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.PARSERS_OVFLW, name, forceAction)
				}
			}
		},
	}
	cmdPostOverflowsUpgrade.PersistentFlags().BoolVarP(&all, "all", "a", false, "Upgrade all the postoverflows")
	cmdPostOverflowsUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")
	cmdPostOverflows.AddCommand(cmdPostOverflowsUpgrade)

	var cmdPostOverflowsInspect = &cobra.Command{
		Use:               "inspect [config]",
		Short:             "Inspect given postoverflow",
		Long:              `Inspect given postoverflow`,
		Example:           `cscli postoverflows inspect crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS_OVFLW, args, toComplete)
		},
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			InspectItem(args[0], cwhub.PARSERS_OVFLW)
		},
	}
	cmdPostOverflows.AddCommand(cmdPostOverflowsInspect)

	var cmdPostOverflowsList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all postoverflows or given one",
		Long:  `List all postoverflows or given one`,
		Example: `cscli postoverflows list
cscli postoverflows list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems([]string{cwhub.PARSERS_OVFLW}, args, false, true, all)
		},
	}
	cmdPostOverflowsList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")
	cmdPostOverflows.AddCommand(cmdPostOverflowsList)

	return cmdPostOverflows
}
