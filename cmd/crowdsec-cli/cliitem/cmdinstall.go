package cliitem

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agext/levenshtein"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

// suggestNearestMessage returns a message with the most similar item name, if one is found
func suggestNearestMessage(hub *cwhub.Hub, itemType string, itemName string) string {
	const maxDistance = 7

	score := 100
	nearest := ""

	for _, item := range hub.GetItemsByType(itemType, false) {
		d := levenshtein.Distance(itemName, item.Name, nil)
		if d < score {
			score = d
			nearest = item.Name
		}
	}

	msg := fmt.Sprintf("can't find '%s' in %s", itemName, itemType)

	if score < maxDistance {
		msg += fmt.Sprintf(", did you mean '%s'?", nearest)
	}

	return msg
}

func (cli cliItem) install(ctx context.Context, args []string, interactive bool, dryRun bool, downloadOnly bool, force bool, ignoreError bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, log.StandardLogger())
	if err != nil {
		return err
	}

	plan := hubops.NewActionPlan(hub)

	contentProvider := require.HubDownloader(ctx, cfg)

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			msg := suggestNearestMessage(hub, cli.name, name)
			if !ignoreError {
				return errors.New(msg)
			}

			log.Error(msg)

			continue
		}

		if err = plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, force)); err != nil {
			return err
		}

		if !downloadOnly {
			if err = plan.AddCommand(hubops.NewEnableCommand(item, force)); err != nil {
				return err
			}
		}
	}

	showPlan := (log.StandardLogger().Level >= log.InfoLevel)
	verbosePlan := (cfg.Cscli.Output == "raw")

	if err := plan.Execute(ctx, interactive, dryRun, showPlan, verbosePlan); err != nil {
		if !ignoreError {
			return err
		}

		log.Error(err)
	}

	if msg := reload.UserMessage(); msg != "" && plan.ReloadNeeded {
		fmt.Println("\n" + msg)
	}

	return nil
}

func compAllItems(itemType string, args []string, toComplete string, cfg configGetter) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(cfg(), nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)

	for _, item := range hub.GetItemsByType(itemType, false) {
		if !slices.Contains(args, item.Name) && strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}

func (cli cliItem) newInstallCmd() *cobra.Command {
	var (
		interactive  bool
		dryRun       bool
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
			return cli.install(cmd.Context(), args, interactive, dryRun, downloadOnly, force, ignoreError)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "Don't install or remove anything; print the execution plan")
	flags.BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	flags.BoolVar(&force, "force", false, "Force install: overwrite tainted and outdated files")
	flags.BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple "+cli.name)
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

	return cmd
}
