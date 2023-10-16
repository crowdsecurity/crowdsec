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
		Use:   "collections <action> [collection]...",
		Short: "Manage hub collections",
		Example: `cscli collections list -a
cscli collections install crowdsecurity/http-cve crowdsecurity/iptables
cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables
cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables
cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables
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
		Use:               "install <collection>...",
		Short:             "Install given collection(s)",
		Long:              `Fetch and install one or more collections from hub`,
		Example:           `cscli collections install crowdsecurity/http-cve crowdsecurity/iptables`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsInstall,
	}

	flags := cmdCollectionsInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
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
				// XXX: this should be in GetItem?
				return fmt.Errorf("can't find '%s' in %s", name, cwhub.COLLECTIONS)
			}
			if len(item.BelongsToCollections) > 0 {
				log.Warningf("%s belongs to other collections: %s", name, item.BelongsToCollections)
				log.Warningf("Run 'sudo cscli collections remove %s --force' if you want to force remove this sub collection", name)
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
		Use:               "remove <collection>...",
		Short:             "Remove given collection(s)",
		Long:              `Remove one or more collections`,
		Example:           `cscli collections remove crowdsecurity/http-cve crowdsecurity/iptables`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsRemove,
	}

	flags := cmdCollectionsRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the collections")

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
		if err := cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, "", force); err != nil {
			return err
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one collection to upgrade or '--all'")
	}

	for _, name := range args {
		if err := cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, name, force); err != nil {
			return err
		}
	}

	return nil
}

func NewCollectionsUpgradeCmd() *cobra.Command {
	cmdCollectionsUpgrade := &cobra.Command{
		Use:               "upgrade <collection>...",
		Short:             "Upgrade given collection(s)",
		Long:              `Fetch and upgrade one or more collections from the hub`,
		Example:           `cscli collections upgrade crowdsecurity/http-cve crowdsecurity/iptables`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsUpgrade,
	}

	flags := cmdCollectionsUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the collections")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

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

	noMetrics, err := flags.GetBool("no-metrics")
	if err != nil {
		return err
	}

	for _, name := range args {
		if err = InspectItem(name, cwhub.COLLECTIONS, noMetrics); err != nil {
			return err
		}
	}

	return nil
}

func NewCollectionsInspectCmd() *cobra.Command {
	cmdCollectionsInspect := &cobra.Command{
		Use:               "inspect <collection>...",
		Short:             "Inspect given collection(s)",
		Long:              `Inspect one or more collections`,
		Example:           `cscli collections inspect crowdsecurity/http-cve crowdsecurity/iptables`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.COLLECTIONS, args, toComplete)
		},
		RunE: runCollectionsInspect,
	}

	flags := cmdCollectionsInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

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
		Use:   "list [collection... | -a]",
		Short: "List collections",
		Long:  `List of installed/available/specified collections`,
		Example: `cscli collections list
cscli collections list -a
cscli collections list crowdsecurity/http-cve crowdsecurity/iptables`,
		DisableAutoGenTag: true,
		RunE:              runCollectionsList,
	}

	flags := cmdCollectionsList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdCollectionsList
}
