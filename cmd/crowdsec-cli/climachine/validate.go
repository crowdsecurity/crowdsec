package climachine

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func (cli *cliMachines) validate(ctx context.Context, machineID string) error {
	if err := cli.db.ValidateMachine(ctx, machineID); err != nil {
		return fmt.Errorf("unable to validate machine '%s': %w", machineID, err)
	}

	log.Infof("machine '%s' validated successfully", machineID)

	return nil
}

func (cli *cliMachines) newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "validate",
		Short:             "validate a machine to access the local API",
		Long:              `validate a machine to access the local API.`,
		Example:           `cscli machines validate "machine_name"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.validate(cmd.Context(), args[0])
		},
	}

	return cmd
}
