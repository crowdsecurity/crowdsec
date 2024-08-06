package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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
	cfg           configGetter
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
		Use:               cmp.Or(cli.help.use, cli.name+" <action> [item]..."),
		Short:             cmp.Or(cli.help.short, "Manage hub "+cli.name),
		Long:              cli.help.long,
		Example:           cli.help.example,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{cli.singular},
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newInstallCmd())
	cmd.AddCommand(cli.newRemoveCmd())
	cmd.AddCommand(cli.newUpgradeCmd())
	cmd.AddCommand(cli.newInspectCmd())
	cmd.AddCommand(cli.newListCmd())

	return cmd
}

func (cli cliItem) install(ctx context.Context, args []string, downloadOnly bool, force bool, ignoreError bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, require.RemoteHub(ctx, cfg), log.StandardLogger())
	if err != nil {
		return err
	}

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			msg := suggestNearestMessage(hub, cli.name, name)
			if !ignoreError {
				return errors.New(msg)
			}

			log.Errorf(msg)

			continue
		}

		if err := item.Install(ctx, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", item.Name, err)
			}

			log.Errorf("Error while installing '%s': %s", item.Name, err)
		}
	}

	log.Infof(ReloadMessage())

	return nil
}

func (cli cliItem) newInstallCmd() *cobra.Command {
	var (
		downloadOnly bool
		force        bool
		ignoreError  bool
	)

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.installHelp.use, "install [item]..."),
		Short:             cmp.Or(cli.installHelp.short, "Install given "+cli.oneOrMore),
		Long:              cmp.Or(cli.installHelp.long, fmt.Sprintf("Fetch and install one or more %s from the hub", cli.name)),
		Example:           cli.installHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cli.name, args, toComplete, cli.cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.install(cmd.Context(), args, downloadOnly, force, ignoreError)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	flags.BoolVar(&force, "force", false, "Force install: overwrite tainted and outdated files")
	flags.BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple "+cli.name)

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

func (cli cliItem) remove(args []string, purge bool, force bool, all bool) error {
	hub, err := require.Hub(cli.cfg(), nil, log.StandardLogger())
	if err != nil {
		return err
	}

	if all {
		itemGetter := hub.GetInstalledByType
		if purge {
			itemGetter = hub.GetItemsByType
		}

		removed := 0

		for _, item := range itemGetter(cli.name, true) {
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

func (cli cliItem) newRemoveCmd() *cobra.Command {
	var (
		purge bool
		force bool
		all   bool
	)

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.removeHelp.use, "remove [item]..."),
		Short:             cmp.Or(cli.removeHelp.short, "Remove given "+cli.oneOrMore),
		Long:              cmp.Or(cli.removeHelp.long, "Remove one or more "+cli.name),
		Example:           cli.removeHelp.example,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete, cli.cfg)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.remove(args, purge, force, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&purge, "purge", false, "Delete source file too")
	flags.BoolVar(&force, "force", false, "Force remove: remove tainted and outdated files")
	flags.BoolVar(&all, "all", false, "Remove all the "+cli.name)

	return cmd
}

func (cli cliItem) upgrade(ctx context.Context, args []string, force bool, all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, require.RemoteHub(ctx, cfg), log.StandardLogger())
	if err != nil {
		return err
	}

	if all {
		updated := 0

		for _, item := range hub.GetInstalledByType(cli.name, true) {
			didUpdate, err := item.Upgrade(ctx, force)
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

		didUpdate, err := item.Upgrade(ctx, force)
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

func (cli cliItem) newUpgradeCmd() *cobra.Command {
	var (
		all   bool
		force bool
	)

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.upgradeHelp.use, "upgrade [item]..."),
		Short:             cmp.Or(cli.upgradeHelp.short, "Upgrade given "+cli.oneOrMore),
		Long:              cmp.Or(cli.upgradeHelp.long, fmt.Sprintf("Fetch and upgrade one or more %s from the hub", cli.name)),
		Example:           cli.upgradeHelp.example,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete, cli.cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.upgrade(cmd.Context(), args, force, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&all, "all", "a", false, "Upgrade all the "+cli.name)
	flags.BoolVar(&force, "force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func (cli cliItem) inspect(ctx context.Context, args []string, url string, diff bool, rev bool, noMetrics bool) error {
	cfg := cli.cfg()

	if rev && !diff {
		return errors.New("--rev can only be used with --diff")
	}

	if url != "" {
		cfg.Cscli.PrometheusUrl = url
	}

	remote := (*cwhub.RemoteHubCfg)(nil)

	if diff {
		remote = require.RemoteHub(ctx, cfg)
	}

	hub, err := require.Hub(cfg, remote, log.StandardLogger())
	if err != nil {
		return err
	}

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", name, cli.name)
		}

		if diff {
			fmt.Println(cli.whyTainted(ctx, hub, item, rev))

			continue
		}

		if err = inspectItem(item, !noMetrics, cfg.Cscli.Output, cfg.Cscli.PrometheusUrl, cfg.Cscli.Color); err != nil {
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

func (cli cliItem) newInspectCmd() *cobra.Command {
	var (
		url       string
		diff      bool
		rev       bool
		noMetrics bool
	)

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.inspectHelp.use, "inspect [item]..."),
		Short:             cmp.Or(cli.inspectHelp.short, "Inspect given "+cli.oneOrMore),
		Long:              cmp.Or(cli.inspectHelp.long, "Inspect the state of one or more "+cli.name),
		Example:           cli.inspectHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete, cli.cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.inspect(cmd.Context(), args, url, diff, rev, noMetrics)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Prometheus url")
	flags.BoolVar(&diff, "diff", false, "Show diff with latest version (for tainted items)")
	flags.BoolVar(&rev, "rev", false, "Reverse diff output")
	flags.BoolVar(&noMetrics, "no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmd
}

func (cli cliItem) list(args []string, all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cli.cfg(), nil, log.StandardLogger())
	if err != nil {
		return err
	}

	items := make(map[string][]*cwhub.Item)

	items[cli.name], err = selectItems(hub, cli.name, args, !all)
	if err != nil {
		return err
	}

	return listItems(color.Output, cfg.Cscli.Color, []string{cli.name}, items, false, cfg.Cscli.Output)
}

func (cli cliItem) newListCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.listHelp.use, "list [item... | -a]"),
		Short:             cmp.Or(cli.listHelp.short, "List "+cli.oneOrMore),
		Long:              cmp.Or(cli.listHelp.long, "List of installed/available/specified "+cli.name),
		Example:           cli.listHelp.example,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.list(args, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmd
}

// return the diff between the installed version and the latest version
func (cli cliItem) itemDiff(ctx context.Context, item *cwhub.Item, reverse bool) (string, error) {
	if !item.State.Installed {
		return "", fmt.Errorf("'%s' is not installed", item.FQName())
	}

	dest, err := os.CreateTemp("", "cscli-diff-*")
	if err != nil {
		return "", fmt.Errorf("while creating temporary file: %w", err)
	}
	defer os.Remove(dest.Name())

	_, remoteURL, err := item.FetchContentTo(ctx, dest.Name())
	if err != nil {
		return "", err
	}

	latestContent, err := os.ReadFile(dest.Name())
	if err != nil {
		return "", fmt.Errorf("while reading %s: %w", dest.Name(), err)
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

func (cli cliItem) whyTainted(ctx context.Context, hub *cwhub.Hub, item *cwhub.Item, reverse bool) string {
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

		diff, err := cli.itemDiff(ctx, sub, reverse)
		if err != nil {
			ret = append(ret, err.Error())
		}

		if diff != "" {
			ret = append(ret, diff)
		} else if len(sub.State.TaintedBy) > 0 {
			taintList := strings.Join(sub.State.TaintedBy, ", ")
			if sub.FQName() == taintList {
				// hack: avoid message "item is tainted by itself"
				continue
			}

			ret = append(ret, fmt.Sprintf("# %s is tainted by %s", sub.FQName(), taintList))
		}
	}

	return strings.Join(ret, "\n")
}
