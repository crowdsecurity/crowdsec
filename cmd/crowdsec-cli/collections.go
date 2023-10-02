package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCollectionsCmd() *cobra.Command {
	var cmdCollections = &cobra.Command{
		Use:   "collections [action]",
		Short: "Manage collections from hub",
		Long:  `Install/Remove/Upgrade/Inspect collections from the CrowdSec Hub.`,
		/*TBD fix help*/
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"collection"},
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

	var ignoreError bool

	var cmdCollectionsInstall = &cobra.Command{
		Use:     "install collection",
		Short:   "Install given collection(s)",
		Long:    `Fetch and install given collection(s) from hub`,
		Example: `cscli collections install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.COLLECTIONS, args, toComplete)
		},
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.COLLECTIONS, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.COLLECTIONS, name)
					Suggest(cwhub.COLLECTIONS, name, nearestItem.Name, score, ignoreError)
					continue
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.COLLECTIONS, forceAction, downloadOnly); err != nil {
					if !ignoreError {
						return fmt.Errorf("error while installing '%s': %w", name, err)
					}
					log.Errorf("Error while installing '%s': %s", name, err)
				}
			}
			return nil
		},
	}
	cmdCollectionsInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdCollectionsInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdCollectionsInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple collections")
	cmdCollections.AddCommand(cmdCollectionsInstall)

	var cmdCollectionsRemove = &cobra.Command{
		Use:               "remove collection",
		Short:             "Remove given collection(s)",
		Long:              `Remove given collection(s) from hub`,
		Example:           `cscli collections remove crowdsec/xxx crowdsec/xyz`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.COLLECTIONS, "", all, purge, forceAction)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("specify at least one collection to remove or '--all'")
			}

			for _, name := range args {
				if !forceAction {
					item := cwhub.GetItem(cwhub.COLLECTIONS, name)
					if item == nil {
						return fmt.Errorf("unable to retrieve: %s", name)
					}
					if len(item.BelongsToCollections) > 0 {
						log.Warningf("%s belongs to other collections :\n%s\n", name, item.BelongsToCollections)
						log.Printf("Run 'sudo cscli collections remove %s --force' if you want to force remove this sub collection\n", name)
						continue
					}
				}
				cwhub.RemoveMany(csConfig, cwhub.COLLECTIONS, name, all, purge, forceAction)
			}
			return nil
		},
	}
	cmdCollectionsRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdCollectionsRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdCollectionsRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the collections")
	cmdCollections.AddCommand(cmdCollectionsRemove)

	var cmdCollectionsUpgrade = &cobra.Command{
		Use:               "upgrade collection",
		Short:             "Upgrade given collection(s)",
		Long:              `Fetch and upgrade given collection(s) from hub`,
		Example:           `cscli collections upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, "", forceAction)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one collection to upgrade or '--all'")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, name, forceAction)
				}
			}
			return nil
		},
	}
	cmdCollectionsUpgrade.PersistentFlags().BoolVarP(&all, "all", "a", false, "Upgrade all the collections")
	cmdCollectionsUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")
	cmdCollections.AddCommand(cmdCollectionsUpgrade)

	var cmdCollectionsInspect = &cobra.Command{
		Use:               "inspect collection",
		Short:             "Inspect given collection",
		Long:              `Inspect given collection`,
		Example:           `cscli collections inspect crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range args {
				InspectItem(name, cwhub.COLLECTIONS)
			}
		},
	}
	cmdCollectionsInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url")
	cmdCollections.AddCommand(cmdCollectionsInspect)

	var cmdCollectionsList = &cobra.Command{
		Use:               "list collection [-a]",
		Short:             "List all collections",
		Long:              `List all collections`,
		Example:           `cscli collections list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems(color.Output, []string{cwhub.COLLECTIONS}, args, false, true, all)
		},
	}
	cmdCollectionsList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")
	cmdCollections.AddCommand(cmdCollectionsList)

	return cmdCollections
}
