package clisetup

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

func (cli *cliSetup) newInstallHubCmd() *cobra.Command {
	var (
		interactive bool
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:               "install-hub [setup_file] [flags]",
		Short:             "install items from a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputReader, err := maybeStdinFile(args[0])
			if err != nil {
				return err
			}

			builder := setup.NewSetupBuilder(logrus.StandardLogger())

			stup, err := builder.FromYAML(inputReader, true, cli.cfg().Cscli.Color != "no")
			if err != nil {
				return err
			}

			return cli.install(cmd.Context(), interactive, dryRun, stup.CollectHubSpecs())
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "don't install anything; print out what would have been")
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

	return cmd
}

func (cli *cliSetup) install(ctx context.Context, interactive bool, dryRun bool, hubSpecs []setup.HubSpec) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, logrus.StandardLogger())
	if err != nil {
		return err
	}

	contentProvider := require.HubDownloader(ctx, cfg)

	showPlan := interactive
	// in dry-run, it can be useful to see the _order_ in which files are installed.
	verbosePlan := dryRun

	plan := hubops.NewActionPlan(hub)

	for _, itemMap := range hubSpecs {
		for itemType, itemNames := range itemMap {
			for _, itemName := range itemNames {
				fqName := itemType + ":" + itemName

				item, err := hub.GetItemFQ(fqName)
				if err != nil {
					return err
				}

				if err := plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, false)); err != nil {
					return err
				}

				if err := plan.AddCommand(hubops.NewEnableCommand(item, false)); err != nil {
					return err
				}
			}
		}
	}

	return plan.Execute(ctx, interactive, dryRun, showPlan, verbosePlan)
}
