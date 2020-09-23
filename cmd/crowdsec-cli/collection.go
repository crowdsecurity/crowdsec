package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewCollectionCmd() *cobra.Command {
	var cmdCollection = &cobra.Command{
		Use:   "collection [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect collection(s) from hub",
		Long: `
		Install/Remove/Upgrade/Inspect collection(s) from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[action] must be install/upgrade or remove.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
`,
		Example: `cscli install [type] [config_name]`,
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

	var cmdCollectionInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given collection",
		Long:    `Fetch and install given collection from hub`,
		Example: `cscli collection install crowdsec/xxx`,
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
	cmdCollectionInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollection.AddCommand(cmdCollectionInstall)

	var cmdCollectionRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given collection",
		Long:    `Remove given collection from hub`,
		Example: `cscli collection remove crowdsec/xxx`,
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
	cmdCollectionRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdCollectionRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdCollection.AddCommand(cmdCollectionRemove)

	var cmdCollectionUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given collection",
		Long:    `Fetch and upgrade given collection from hub`,
		Example: `cscli collection upgrade crowdsec/xxx`,
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
	cmdCollectionUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollection.AddCommand(cmdCollectionUpgrade)

	var cmdCollectionInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given collection",
		Long:    `Inspect given collection`,
		Example: `cscli collection inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.COLLECTIONS)
		},
	}
	cmdCollectionInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdCollection.AddCommand(cmdCollectionInspect)

	var cmdCollectionList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all collection or given one",
		Long:  `List all collection or given one`,
		Example: `cscli collection list
cscli collection list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.COLLECTIONS, args)
		},
	}
	cmdCollection.AddCommand(cmdCollectionList)

	return cmdCollection
}
