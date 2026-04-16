package clibouncer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/ask"
)

const defaultPruneDuration = 60 * time.Minute

func (cli *cliBouncers) prune(ctx context.Context, duration time.Duration, force bool) error {
	if duration < 2*time.Minute {
		if yes, err := ask.YesNo(
			"The duration you provided is less than 2 minutes. "+
				"This may remove active bouncers. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Fprintln(os.Stdout, "User aborted prune. No changes were made.")
			return nil
		}
	}

	bouncers, err := cli.db.QueryBouncersInactiveSince(ctx, time.Now().UTC().Add(-duration))
	if err != nil {
		return fmt.Errorf("unable to query bouncers: %w", err)
	}

	if len(bouncers) == 0 {
		fmt.Fprintln(os.Stdout, "No bouncers to prune.")
		return nil
	}

	cli.listHuman(color.Output, bouncers)

	if !force {
		if yes, err := ask.YesNo(
			"You are about to PERMANENTLY remove the above bouncers from the database. "+
				"These will NOT be recoverable. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Fprintln(os.Stdout, "User aborted prune. No changes were made.")
			return nil
		}
	}

	deleted, err := cli.db.BulkDeleteBouncers(ctx, bouncers)
	if err != nil {
		return fmt.Errorf("unable to prune bouncers: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully deleted %d bouncers\n", deleted)

	return nil
}

func (cli *cliBouncers) newPruneCmd() *cobra.Command {
	var force bool

	duration := cstime.DurationWithDays(defaultPruneDuration)

	cmd := &cobra.Command{
		Use:               "prune",
		Short:             "prune multiple bouncers from the database",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		Example: `cscli bouncers prune -d 45m
cscli bouncers prune -d 45m --force`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.prune(cmd.Context(), time.Duration(duration), force)
		},
	}

	flags := cmd.Flags()
	flags.VarP(&duration, "duration", "d", "duration of time since last pull")
	flags.BoolVar(&force, "force", false, "force prune without asking for confirmation")

	return cmd
}
