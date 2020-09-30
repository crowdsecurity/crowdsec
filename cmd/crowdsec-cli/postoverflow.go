package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewPostOverflowCmd() *cobra.Command {
	var cmdPostOverflow = &cobra.Command{
		Use:   "postoverflow [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect postoverflow(s) from hub",
		Long: `
		Install/Remove/Upgrade/Inspect postoverflow(s) from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[action] must be install/upgrade or remove.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).

As a reminder, postoverflows are parsing configuration that will occur after the overflow (before a decision is applied)
`,
		Example: `cscli postoverflow [action] [config_name]`,
		Args:    cobra.MinimumNArgs(1),
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
	cmdPostOverflow.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

	var cmdPostOverflowInstall = &cobra.Command{
		Use:     "postoverflow [config]",
		Short:   "Install given postoverflow",
		Long:    `Fetch and install given postoverflow from hub`,
		Example: `cscli postoverflow install crowdsec/xxx`,
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
	cmdPostOverflowInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflow.AddCommand(cmdPostOverflowInstall)

	var cmdPostOverflowRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given postoverflow",
		Long:    `remove given postoverflow`,
		Example: `cscli postoverflow remove crowdsec/xxx`,
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
	cmdPostOverflowRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdPostOverflowRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdPostOverflow.AddCommand(cmdPostOverflowRemove)

	var cmdPostOverflowUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given postoverflow",
		Long:    `Fetch and Upgrade given postoverflow from hub`,
		Example: `cscli postoverflow upgrade crowdsec/xxx`,
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
	cmdPostOverflowUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdPostOverflowUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdPostOverflow.AddCommand(cmdPostOverflowUpgrade)

	var cmdPostOverflowInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given postoverflow",
		Long:    `Inspect given postoverflow`,
		Example: `cscli postoverflow inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.PARSERS_OVFLW)
		},
	}
	cmdPostOverflow.AddCommand(cmdPostOverflowInspect)

	var cmdPostOverflowList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all postoverflow or given one",
		Long:  `List all postoverflow or given one`,
		Example: `cscli postoverflow list
cscli postoverflow list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdPostOverflow.AddCommand(cmdPostOverflowList)

	return cmdPostOverflow
}
