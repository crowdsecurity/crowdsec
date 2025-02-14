package cliitem

import (
	"cmp"
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

func (cli cliItem) upgradePlan(hub *cwhub.Hub, contentProvider cwhub.ContentProvider, args []string, force bool, all bool) (*hubops.ActionPlan, error) {
	plan := hubops.NewActionPlan(hub)

	if all {
		for _, item := range hub.GetInstalledByType(cli.name, true) {
			if err := plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, force)); err != nil {
				return nil, err
			}
		}

		return plan, nil
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("specify at least one %s to upgrade or '--all'", cli.singular)
	}

	for _, itemName := range args {
		item := hub.GetItem(cli.name, itemName)
		if item == nil {
			return nil, fmt.Errorf("can't find '%s' in %s", itemName, cli.name)
		}

		if err := plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, force)); err != nil {
			return nil, err
		}
	}

	return plan, nil
}

func (cli cliItem) upgrade(ctx context.Context, args []string, interactive bool, dryRun bool, force bool, all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, log.StandardLogger())
	if err != nil {
		return err
	}

	contentProvider := require.HubDownloader(ctx, cfg)

	plan, err := cli.upgradePlan(hub, contentProvider, args, force, all)
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

func (cli cliItem) newUpgradeCmd() *cobra.Command {
	var (
		interactive bool
		dryRun      bool
		all         bool
		force       bool
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
			return cli.upgrade(cmd.Context(), args, interactive, dryRun, force, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "Don't install or remove anything; print the execution plan")
	flags.BoolVarP(&all, "all", "a", false, "Upgrade all the "+cli.name)
	flags.BoolVar(&force, "force", false, "Force upgrade: overwrite tainted and outdated files")
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

	return cmd
}
