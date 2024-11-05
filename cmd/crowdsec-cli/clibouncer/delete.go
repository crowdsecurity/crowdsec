package clibouncer

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func (cli *cliBouncers) delete(ctx context.Context, bouncers []string, ignoreMissing bool) error {
	for _, bouncerID := range bouncers {
		if err := cli.db.DeleteBouncer(ctx, bouncerID); err != nil {
			var notFoundErr *database.BouncerNotFoundError
			if ignoreMissing && errors.As(err, &notFoundErr) {
				return nil
			}

			return fmt.Errorf("unable to delete bouncer: %w", err)
		}

		log.Infof("bouncer '%s' deleted successfully", bouncerID)
	}

	return nil
}

func (cli *cliBouncers) newDeleteCmd() *cobra.Command {
	var ignoreMissing bool

	cmd := &cobra.Command{
		Use:               "delete MyBouncerName",
		Short:             "delete bouncer(s) from the database",
		Example:           `cscli bouncers delete "bouncer1" "bouncer2"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validBouncerID,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.delete(cmd.Context(), args, ignoreMissing)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&ignoreMissing, "ignore-missing", false, "don't print errors if one or more bouncers don't exist")

	return cmd
}
