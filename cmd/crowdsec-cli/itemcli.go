package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/coalesce"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cliHelp struct {
	// Example is required, the others have a default value
	// generated from the item type
	use     string
	short   string
	long    string
	example string
}

type cliItem struct {
	name          string // plural, as used in the hub index
	singular      string
	oneOrMore     string // parenthetical pluralizaion: "parser(s)"
	help          cliHelp
	installHelp   cliHelp
	removeHelp    cliHelp
	upgradeHelp   cliHelp
	inspectHelp   cliHelp
	inspectDetail func(item *cwhub.Item) error
	listHelp      cliHelp
}

func (cli cliItem) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.help.use, fmt.Sprintf("%s <action> [item]...", cli.name)),
		Short:             coalesce.String(cli.help.short, fmt.Sprintf("Manage hub %s", cli.name)),
		Long:              cli.help.long,
		Example:           cli.help.example,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{cli.singular},
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.NewInstallCmd())
	cmd.AddCommand(cli.NewRemoveCmd())
	cmd.AddCommand(cli.NewUpgradeCmd())
	cmd.AddCommand(cli.NewInspectCmd())
	cmd.AddCommand(cli.NewListCmd())

	return cmd
}

func (cli cliItem) Install(cmd *cobra.Command, args []string) error {
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

	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig), log.StandardLogger())
	if err != nil {
		return err
	}

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			msg := suggestNearestMessage(hub, cli.name, name)
			if !ignoreError {
				return fmt.Errorf(msg)
			}

			log.Errorf(msg)

			continue
		}

		if err := item.Install(force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", item.Name, err)
			}
			log.Errorf("Error while installing '%s': %s", item.Name, err)
		}
	}

	log.Infof(ReloadMessage())
	return nil
}

func (cli cliItem) NewInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.installHelp.use, "install [item]..."),
		Short:             coalesce.String(cli.installHelp.short, fmt.Sprintf("Install given %s", cli.oneOrMore)),
		Long:              coalesce.String(cli.installHelp.long, fmt.Sprintf("Fetch and install one or more %s from the hub", cli.name)),
		Example:           cli.installHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cli.name, args, toComplete)
		},
		RunE: cli.Install,
	}

	flags := cmd.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, fmt.Sprintf("Ignore errors when installing multiple %s", cli.name))

	return cmd
}

// return the names of the installed parents of an item, used to check if we can remove it
func istalledParentNames(item *cwhub.Item) []string {
	ret := make([]string, 0)

	for _, parent := range item.Ancestors() {
		if parent.State.Installed {
			ret = append(ret, parent.Name)
		}
	}

	return ret
}

func (cli cliItem) Remove(cmd *cobra.Command, args []string) error {
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

	hub, err := require.Hub(csConfig, nil, log.StandardLogger())
	if err != nil {
		return err
	}

	if all {
		getter := hub.GetInstalledItems
		if purge {
			getter = hub.GetAllItems
		}

		items, err := getter(cli.name)
		if err != nil {
			return err
		}

		removed := 0

		for _, item := range items {
			didRemove, err := item.Remove(purge, force)
			if err != nil {
				return err
			}
			if didRemove {
				log.Infof("Removed %s", item.Name)
				removed++
			}
		}

		log.Infof("Removed %d %s", removed, cli.name)
		if removed > 0 {
			log.Infof(ReloadMessage())
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one %s to remove or '--all'", cli.singular)
	}

	removed := 0

	for _, itemName := range args {
		item := hub.GetItem(cli.name, itemName)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", itemName, cli.name)
		}

		parents := istalledParentNames(item)

		if !force && len(parents) > 0 {
			log.Warningf("%s belongs to collections: %s", item.Name, parents)
			log.Warningf("Run 'sudo cscli %s remove %s --force' if you want to force remove this %s", item.Type, item.Name, cli.singular)

			continue
		}

		didRemove, err := item.Remove(purge, force)
		if err != nil {
			return err
		}

		if didRemove {
			log.Infof("Removed %s", item.Name)
			removed++
		}
	}

	log.Infof("Removed %d %s", removed, cli.name)
	if removed > 0 {
		log.Infof(ReloadMessage())
	}

	return nil
}

func (cli cliItem) NewRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.removeHelp.use, "remove [item]..."),
		Short:             coalesce.String(cli.removeHelp.short, fmt.Sprintf("Remove given %s", cli.oneOrMore)),
		Long:              coalesce.String(cli.removeHelp.long, fmt.Sprintf("Remove one or more %s", cli.name)),
		Example:           cli.removeHelp.example,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete)
		},
		RunE: cli.Remove,
	}

	flags := cmd.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, fmt.Sprintf("Remove all the %s", cli.name))

	return cmd
}

func (cli cliItem) Upgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig), log.StandardLogger())
	if err != nil {
		return err
	}

	if all {
		items, err := hub.GetInstalledItems(cli.name)
		if err != nil {
			return err
		}

		updated := 0

		for _, item := range items {
			didUpdate, err := item.Upgrade(force)
			if err != nil {
				return err
			}
			if didUpdate {
				updated++
			}
		}

		log.Infof("Updated %d %s", updated, cli.name)

		if updated > 0 {
			log.Infof(ReloadMessage())
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one %s to upgrade or '--all'", cli.singular)
	}

	updated := 0

	for _, itemName := range args {
		item := hub.GetItem(cli.name, itemName)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", itemName, cli.name)
		}

		didUpdate, err := item.Upgrade(force)
		if err != nil {
			return err
		}

		if didUpdate {
			log.Infof("Updated %s", item.Name)
			updated++
		}
	}
	if updated > 0 {
		log.Infof(ReloadMessage())
	}

	return nil
}

func (cli cliItem) NewUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.upgradeHelp.use, "upgrade [item]..."),
		Short:             coalesce.String(cli.upgradeHelp.short, fmt.Sprintf("Upgrade given %s", cli.oneOrMore)),
		Long:              coalesce.String(cli.upgradeHelp.long, fmt.Sprintf("Fetch and upgrade one or more %s from the hub", cli.name)),
		Example:           cli.upgradeHelp.example,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete)
		},
		RunE: cli.Upgrade,
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, fmt.Sprintf("Upgrade all the %s", cli.name))
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func (cli cliItem) Inspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	url, err := flags.GetString("url")
	if err != nil {
		return err
	}

	if url != "" {
		csConfig.Cscli.PrometheusUrl = url
	}

	diff, err := flags.GetBool("diff")
	if err != nil {
		return err
	}

	rev, err := flags.GetBool("rev")
	if err != nil {
		return err
	}

	noMetrics, err := flags.GetBool("no-metrics")
	if err != nil {
		return err
	}

	remote := (*cwhub.RemoteHubCfg)(nil)

	if diff {
		remote = require.RemoteHub(csConfig)
	}

	hub, err := require.Hub(csConfig, remote, log.StandardLogger())
	if err != nil {
		return err
	}

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", name, cli.name)
		}

		if diff {
			fmt.Println(cli.whyTainted(hub, item, rev))

			continue
		}

		if err = InspectItem(item, !noMetrics); err != nil {
			return err
		}

		if cli.inspectDetail != nil {
			if err = cli.inspectDetail(item); err != nil {
				return err
			}
		}
	}

	return nil
}

func (cli cliItem) NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.inspectHelp.use, "inspect [item]..."),
		Short:             coalesce.String(cli.inspectHelp.short, fmt.Sprintf("Inspect given %s", cli.oneOrMore)),
		Long:              coalesce.String(cli.inspectHelp.long, fmt.Sprintf("Inspect the state of one or more %s", cli.name)),
		Example:           cli.inspectHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete)
		},
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmd.Flags()

			diff, err := flags.GetBool("diff")
			if err != nil {
				return err
			}

			rev, err := flags.GetBool("rev")
			if err != nil {
				return err
			}

			if rev && !diff {
				return fmt.Errorf("--rev can only be used with --diff")
			}

			return nil
		},
		RunE: cli.Inspect,
	}

	flags := cmd.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("diff", false, "Show diff with latest version (for tainted items)")
	flags.Bool("rev", false, "Reverse diff output")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmd
}

func (cli cliItem) List(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, nil, log.StandardLogger())
	if err != nil {
		return err
	}

	items := make(map[string][]*cwhub.Item)

	items[cli.name], err = selectItems(hub, cli.name, args, !all)
	if err != nil {
		return err
	}

	if err = listItems(color.Output, []string{cli.name}, items, false); err != nil {
		return err
	}

	return nil
}

func (cli cliItem) NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               coalesce.String(cli.listHelp.use, "list [item... | -a]"),
		Short:             coalesce.String(cli.listHelp.short, fmt.Sprintf("List %s", cli.oneOrMore)),
		Long:              coalesce.String(cli.listHelp.long, fmt.Sprintf("List of installed/available/specified %s", cli.name)),
		Example:           cli.listHelp.example,
		DisableAutoGenTag: true,
		RunE:              cli.List,
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmd
}

// return the diff between the installed version and the latest version
func (cli cliItem) itemDiff(item *cwhub.Item, reverse bool) (string, error) {
	if !item.State.Installed {
		return "", fmt.Errorf("'%s' is not installed", item.FQName())
	}

	latestContent, remoteURL, err := item.FetchLatest()
	if err != nil {
		return "", err
	}

	localContent, err := os.ReadFile(item.State.LocalPath)
	if err != nil {
		return "", fmt.Errorf("while reading %s: %w", item.State.LocalPath, err)
	}

	file1 := item.State.LocalPath
	file2 := remoteURL
	content1 := string(localContent)
	content2 := string(latestContent)
	if reverse {
		file1, file2 = file2, file1
		content1, content2 = content2, content1
	}

	edits := myers.ComputeEdits(span.URIFromPath(file1), content1, content2)
	diff := gotextdiff.ToUnified(file1, file2, content1, edits)

	return fmt.Sprintf("%s", diff), nil
}

func (cli cliItem) whyTainted(hub *cwhub.Hub, item *cwhub.Item, reverse bool) string {
	if !item.State.Installed {
		return fmt.Sprintf("# %s is not installed", item.FQName())
	}

	if !item.State.Tainted {
		return fmt.Sprintf("# %s is not tainted", item.FQName())
	}

	if len(item.State.TaintedBy) == 0 {
		return fmt.Sprintf("# %s is tainted but we don't know why. please report this as a bug", item.FQName())
	}

	ret := []string{
		fmt.Sprintf("# Let's see why %s is tainted.", item.FQName()),
	}

	for _, fqsub := range item.State.TaintedBy {
		ret = append(ret, fmt.Sprintf("\n-> %s\n", fqsub))

		sub, err := hub.GetItemFQ(fqsub)
		if err != nil {
			ret = append(ret, err.Error())
		}

		diff, err := cli.itemDiff(sub, reverse)
		if err != nil {
			ret = append(ret, err.Error())
		}

		if diff != "" {
			ret = append(ret, diff)
		} else if len(sub.State.TaintedBy) > 0 {
			taintList := strings.Join(sub.State.TaintedBy, ", ")
			ret = append(ret, fmt.Sprintf("# %s is tainted by %s", sub.FQName(), taintList))
		}
	}

	return strings.Join(ret, "\n")
}
