package clisetup

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
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
			return cli.install(cmd.Context(), interactive, dryRun, args[0])
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "don't install anything; print out what would have been")
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

	return cmd
}

func (cli *cliSetup) install(ctx context.Context, interactive bool, dryRun bool, fromFile string) error {
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading file %s: %w", fromFile, err)
	}

	cfg := cli.cfg()

	hub, err := require.Hub(cfg, log.StandardLogger())
	if err != nil {
		return err
	}

	contentProvider := require.HubDownloader(ctx, cfg)

	showPlan := (log.StandardLogger().Level >= log.InfoLevel)
	verbosePlan := (cfg.Cscli.Output == "raw")

	return setup.InstallHubItems(ctx, hub, contentProvider, input, interactive, dryRun, showPlan, verbosePlan)
}
