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
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof("Run 'systemctl reload crowdsec' for the new configuration to be effective.")
		},
	}
	cmdPostOverflows.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

	var cmdPostOverflowsInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given postoverflow(s)",
		Long:    `Fetch and install given postoverflow(s) from hub`,
		Example: `cscli postoverflows install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.PARSERS_OVFLW)
			}
		},
	}
	cmdPostOverflowsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowsInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflows.AddCommand(cmdPostOverflowsInstall)

	var cmdPostOverflowsRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given postoverflow(s)",
		Long:    `remove given postoverflow(s)`,
		Example: `cscli postoverflows remove crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			if removeAll {
				RemoveMany(cwhub.PARSERS_OVFLW, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.PARSERS_OVFLW, name)
				}
			}
		},
	}
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdPostOverflowsRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdPostOverflows.AddCommand(cmdPostOverflowsRemove)

	var cmdPostOverflowsUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given postoverflow(s)",
		Long:    `Fetch and Upgrade given postoverflow(s) from hub`,
		Example: `cscli postoverflows upgrade crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgradeAll {
				UpgradeConfig(cwhub.PARSERS_OVFLW, "")
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.PARSERS_OVFLW, name)
				}
			}
		},
	}
	cmdPostOverflowsUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowsUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflows.AddCommand(cmdPostOverflowsUpgrade)

	var cmdPostOverflowsInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given postoverflow",
		Long:    `Inspect given postoverflow`,
		Example: `cscli postoverflows inspect crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
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
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdPostOverflowsList.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")
	cmdPostOverflows.AddCommand(cmdPostOverflowsList)

	return cmdPostOverflows
}
