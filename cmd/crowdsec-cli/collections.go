package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewCollectionsCmd() *cobra.Command {
	var cmdCollections = &cobra.Command{
		Use:   "collections [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect collections from hub",
		Long: `
		Install/Remove/Upgrade/Inspect collections from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[action] must be install/upgrade or remove.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
`,
		Example: `cscli collections install [config_name]`,
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
	cmdCollections.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

	var cmdCollectionsInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given collection(s)",
		Long:    `Fetch and install given collection(s) from hub`,
		Example: `cscli collections install crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.COLLECTIONS)
			}
		},
	}
	cmdCollectionsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionsInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollections.AddCommand(cmdCollectionsInstall)

	var cmdCollectionsRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given collection(s)",
		Long:    `Remove given collection(s) from hub`,
		Example: `cscli collections remove crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			if removeAll {
				RemoveMany(cwhub.COLLECTIONS, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.COLLECTIONS, name)
				}
			}
		},
	}
	cmdCollectionsRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdCollectionsRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdCollections.AddCommand(cmdCollectionsRemove)

	var cmdCollectionsUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given collection(s)",
		Long:    `Fetch and upgrade given collection(s) from hub`,
		Example: `cscli collections upgrade crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgradeAll {
				UpgradeConfig(cwhub.COLLECTIONS, "")
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.COLLECTIONS, name)
				}
			}
		},
	}
	cmdCollectionsUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionsUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollections.AddCommand(cmdCollectionsUpgrade)

	var cmdCollectionsInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given collection",
		Long:    `Inspect given collection`,
		Example: `cscli collections inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.COLLECTIONS)
		},
	}
	cmdCollectionsInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdCollections.AddCommand(cmdCollectionsInspect)

	var cmdCollectionsList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all collections or given one",
		Long:  `List all collections or given one`,
		Example: `cscli collections list
cscli collections list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.COLLECTIONS, args)
		},
	}
	cmdCollectionsList.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")
	cmdCollections.AddCommand(cmdCollectionsList)

	return cmdCollections
}
