package cliitem

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

func (cli cliItem) removePlan(hub *cwhub.Hub, args []string, purge bool, force bool, all bool) (*hubops.ActionPlan, error) {
	plan := hubops.NewActionPlan(hub)

	if all {
		itemGetter := hub.GetInstalledByType
		if purge {
			itemGetter = hub.GetItemsByType
		}

		for _, item := range itemGetter(cli.name, true) {
			if err := plan.AddCommand(hubops.NewDisableCommand(item, force)); err != nil {
				return nil, err
			}

			if purge {
				if err := plan.AddCommand(hubops.NewPurgeCommand(item, force)); err != nil {
					return nil, err
				}
			}
		}

		return plan, nil
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("specify at least one %s to remove or '--all'", cli.singular)
	}

	for _, itemName := range args {
		item := hub.GetItem(cli.name, itemName)
		if item == nil {
			return nil, fmt.Errorf("can't find '%s' in %s", itemName, cli.name)
		}

		parents := installedParentNames(item)

		if !force && len(parents) > 0 {
			log.Warningf("%s belongs to collections: %s", item.Name, parents)
			log.Warningf("Run 'sudo cscli %s remove %s --force' if you want to force remove this %s", item.Type, item.Name, cli.singular)

			continue
		}

		if err := plan.AddCommand(hubops.NewDisableCommand(item, force)); err != nil {
			return nil, err
		}

		if purge {
			if err := plan.AddCommand(hubops.NewPurgeCommand(item, force)); err != nil {
				return nil, err
			}
		}
	}

	return plan, nil
}

// return the names of the installed parents of an item, used to check if we can remove it
func installedParentNames(item *cwhub.Item) []string {
	ret := make([]string, 0)

	for _, parent := range item.Ancestors() {
		if parent.State.Installed {
			ret = append(ret, parent.Name)
		}
	}

	return ret
}

func (cli cliItem) remove(ctx context.Context, args []string, interactive bool, dryRun bool, purge bool, force bool, all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cli.cfg(), log.StandardLogger())
	if err != nil {
		return err
	}

	plan, err := cli.removePlan(hub, args, purge, force, all)
	if err != nil {
		return err
	}

	showPlan := (log.StandardLogger().Level >= log.InfoLevel)
	verbosePlan := (cfg.Cscli.Output == "raw")

	if err := plan.Execute(ctx, interactive, dryRun, showPlan, verbosePlan); err != nil {
		return err
	}

	if msg := reload.UserMessage(); msg != "" && plan.ReloadNeeded {
		fmt.Println("\n" + msg)
	}

	return nil
}

func (cli cliItem) newRemoveCmd() *cobra.Command {
	var (
		interactive bool
		dryRun      bool
		purge       bool
		force       bool
		all         bool
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && all {
				return errors.New("can't specify items and '--all' at the same time")
			}

			return cli.remove(cmd.Context(), args, interactive, dryRun, purge, force, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "Don't install or remove anything; print the execution plan")
	flags.BoolVar(&purge, "purge", false, "Delete source file too")
	flags.BoolVar(&force, "force", false, "Force remove: remove tainted and outdated files")
	flags.BoolVar(&all, "all", false, "Remove all the "+cli.name)
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

	return cmd
}
