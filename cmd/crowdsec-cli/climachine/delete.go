package climachine

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func (cli *cliMachines) delete(ctx context.Context, machines []string, ignoreMissing bool) error {
	for _, machineID := range machines {
		if err := cli.db.DeleteWatcher(ctx, machineID); err != nil {
			var notFoundErr *database.MachineNotFoundError
			if ignoreMissing && errors.As(err, &notFoundErr) {
				return nil
			}

			log.Errorf("unable to delete machine: %s", err)

			return nil
		}

		log.Infof("machine '%s' deleted successfully", machineID)
	}

	return nil
}

func (cli *cliMachines) newDeleteCmd() *cobra.Command {
	var ignoreMissing bool

	cmd := &cobra.Command{
		Use:               "delete [machine_name]...",
		Short:             "delete machine(s) by name",
		Example:           `cscli machines delete "machine1" "machine2"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validMachineID,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.delete(cmd.Context(), args, ignoreMissing)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&ignoreMissing, "ignore-missing", false, "don't print errors if one or more machines don't exist")

	return cmd
}
