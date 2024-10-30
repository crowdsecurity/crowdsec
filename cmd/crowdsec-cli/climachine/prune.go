package climachine

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/ask"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func (cli *cliMachines) prune(ctx context.Context, duration time.Duration, notValidOnly bool, force bool) error {
	if duration < 2*time.Minute && !notValidOnly {
		if yes, err := ask.YesNo(
			"The duration you provided is less than 2 minutes. "+
				"This can break installations if the machines are only temporarily disconnected. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	machines := []*ent.Machine{}
	if pending, err := cli.db.QueryPendingMachine(ctx); err == nil {
		machines = append(machines, pending...)
	}

	if !notValidOnly {
		if pending, err := cli.db.QueryMachinesInactiveSince(ctx, time.Now().UTC().Add(-duration)); err == nil {
			machines = append(machines, pending...)
		}
	}

	if len(machines) == 0 {
		fmt.Println("No machines to prune.")
		return nil
	}

	cli.listHuman(color.Output, machines)

	if !force {
		if yes, err := ask.YesNo(
			"You are about to PERMANENTLY remove the above machines from the database. "+
				"These will NOT be recoverable. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	deleted, err := cli.db.BulkDeleteWatchers(ctx, machines)
	if err != nil {
		return fmt.Errorf("unable to prune machines: %w", err)
	}

	fmt.Fprintf(os.Stderr, "successfully deleted %d machines\n", deleted)

	return nil
}

func (cli *cliMachines) newPruneCmd() *cobra.Command {
	var (
		duration     time.Duration
		notValidOnly bool
		force        bool
	)

	const defaultDuration = 10 * time.Minute

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "prune multiple machines from the database",
		Long:  `prune multiple machines that are not validated or have not connected to the local API in a given duration.`,
		Example: `cscli machines prune
cscli machines prune --duration 1h
cscli machines prune --not-validated-only --force`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.prune(cmd.Context(), duration, notValidOnly, force)
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", defaultDuration, "duration of time since validated machine last heartbeat")
	flags.BoolVar(&notValidOnly, "not-validated-only", false, "only prune machines that are not validated")
	flags.BoolVar(&force, "force", false, "force prune without asking for confirmation")

	return cmd
}
