package clisetup

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
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

			stup, err := setup.NewSetupFromYAML(inputReader, true, cli.cfg().Cscli.Color != "no")
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

	return setup.InstallHubItems(ctx, hub, contentProvider, hubSpecs, interactive, dryRun, showPlan, verbosePlan)
}
