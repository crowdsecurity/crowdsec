package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewCollectionsCmd() *cobra.Command {
	var cmdCollections = &cobra.Command{
		Use:   "collections [action]",
		Short: "Manage collections from hub",
		Long:  `Install/Remove/Upgrade/Inspect collections from the CrowdSec Hub.`,
		/*TBD fix help*/
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			if cwhub.HubBranch == "" && csConfig.Cscli.HubBranch != "" {
				cwhub.HubBranch = csConfig.Cscli.HubBranch
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
		Use:     "install collection",
		Short:   "Install given collection(s)",
		Long:    `Fetch and install given collection(s) from hub`,
		Example: `cscli collections install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.COLLECTIONS, forceInstall)
			}
		},
	}
	cmdCollectionsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionsInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollections.AddCommand(cmdCollectionsInstall)

	var cmdCollectionsRemove = &cobra.Command{
		Use:     "remove collection",
		Short:   "Remove given collection(s)",
		Long:    `Remove given collection(s) from hub`,
		Example: `cscli collections remove crowdsec/xxx crowdsec/xyz`,
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
	cmdCollectionsRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file too")
	cmdCollectionsRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdCollections.AddCommand(cmdCollectionsRemove)

	var cmdCollectionsUpgrade = &cobra.Command{
		Use:     "upgrade collection",
		Short:   "Upgrade given collection(s)",
		Long:    `Fetch and upgrade given collection(s) from hub`,
		Example: `cscli collections upgrade crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgradeAll {
				UpgradeConfig(cwhub.COLLECTIONS, "", forceUpgrade)
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.COLLECTIONS, name, forceUpgrade)
				}
			}
		},
	}
	cmdCollectionsUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionsUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollections.AddCommand(cmdCollectionsUpgrade)

	var cmdCollectionsInspect = &cobra.Command{
		Use:     "inspect collection",
		Short:   "Inspect given collection",
		Long:    `Inspect given collection`,
		Example: `cscli collections inspect crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InspectItem(name, cwhub.COLLECTIONS)
			}
		},
	}
	cmdCollectionsInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdCollections.AddCommand(cmdCollectionsInspect)

	var cmdCollectionsList = &cobra.Command{
		Use:     "list collection [-a]",
		Short:   "List all collections or given one",
		Long:    `List all collections or given one`,
		Example: `cscli collections list`,
		Args:    cobra.ExactArgs(0),
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
