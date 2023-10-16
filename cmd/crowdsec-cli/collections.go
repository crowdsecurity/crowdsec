package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewCollectionsCmd() *cobra.Command {
	cmdCollections := &cobra.Command{
		Use:   "collections [action]",
		Short: "Install/Remove/Upgrade/Inspect collections from the CrowdSec Hub.",
		Example: `cscli collections install crowdsec/xxx crowdsec/xyz
cscli collections inspect crowdsec/xxx crowdsec/xyz
cscli collections upgrade crowdsec/xxx crowdsec/xyz
cscli collections list
cscli collections remove crowdsec/xxx crowdsec/xyz
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"collection"},
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

	cmdCollections.AddCommand(NewCollectionsInstallCmd())
	cmdCollections.AddCommand(NewCollectionsRemoveCmd())
	cmdCollections.AddCommand(NewCollectionsUpgradeCmd())
	cmdCollections.AddCommand(NewCollectionsInspectCmd())
	cmdCollections.AddCommand(NewCollectionsListCmd())

	return cmdCollections
}

func runCollectionsInstall(cmd *cobra.Command, args []string) error {
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
		t := cwhub.GetItem(cwhub.COLLECTIONS, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.COLLECTIONS, name)
			Suggest(cwhub.COLLECTIONS, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := cwhub.InstallItem(csConfig, name, cwhub.COLLECTIONS, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewCollectionsInstallCmd() *cobra.Command {
	cmdCollectionsInstall := &cobra.Command{
		Use:               "install collection",
		Short:             "Install given collection(s)",
		Long:              `Fetch and install given collection(s) from hub`,
		Example:           `cscli collections install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsInstall,
	}

	flags := cmdCollectionsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install : Overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple collections")

	return cmdCollectionsInstall
}

func runCollectionsRemove(cmd *cobra.Command, args []string) error {
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
		err := cwhub.RemoveMany(csConfig, cwhub.COLLECTIONS, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one collection to remove or '--all'")
	}

	for _, name := range args {
		if !force {
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

		err := cwhub.RemoveMany(csConfig, cwhub.COLLECTIONS, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewCollectionsRemoveCmd() *cobra.Command {
	cmdCollectionsRemove := &cobra.Command{
		Use:               "remove collection",
		Short:             "Remove given collection(s)",
		Long:              `Remove given collection(s) from hub`,
		Example:           `cscli collections remove crowdsec/xxx crowdsec/xyz`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsRemove,
	}

	flags := cmdCollectionsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove : Remove tainted and outdated files")
	flags.Bool("all", false, "Delete all the collections")

	return cmdCollectionsRemove
}

func runCollectionsUpgrade(cmd *cobra.Command, args []string) error {
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
		cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, "", force)
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one collection to upgrade or '--all'")
	}

	for _, name := range args {
		cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, name, force)
	}

	return nil
}

func NewCollectionsUpgradeCmd() *cobra.Command {
	cmdCollectionsUpgrade := &cobra.Command{
		Use:               "upgrade collection",
		Short:             "Upgrade given collection(s)",
		Long:              `Fetch and upgrade given collection(s) from hub`,
		Example:           `cscli collections upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsUpgrade,
	}

	flags := cmdCollectionsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the collections")
	flags.Bool("force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdCollectionsUpgrade
}

func runCollectionsInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	url, err := flags.GetString("url")
	if err != nil {
		return err
	}

	if url != "" {
		csConfig.Cscli.PrometheusUrl = url
	}

	for _, name := range args {
		InspectItem(name, cwhub.COLLECTIONS)
	}

	return nil
}

func NewCollectionsInspectCmd() *cobra.Command {
	cmdCollectionsInspect := &cobra.Command{
		Use:               "inspect collection",
		Short:             "Inspect given collection",
		Long:              `Inspect given collection`,
		Example:           `cscli collections inspect crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsInspect,
	}

	flags := cmdCollectionsInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")

	return cmdCollectionsInspect
}

func runCollectionsList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	// XXX: will happily ignore missing collections
	ListItems(color.Output, []string{cwhub.COLLECTIONS}, args, false, true, all)

	return nil
}

func NewCollectionsListCmd() *cobra.Command {
	cmdCollectionsList := &cobra.Command{
		Use:               "list collection [-a]",
		Short:             "List all collections",
		Long:              `List all collections`,
		Example:           `cscli collections list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runCollectionsList,
	}

	flags := cmdCollectionsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdCollectionsList
}
