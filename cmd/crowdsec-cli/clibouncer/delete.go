package clibouncer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (cli *cliBouncers) findParentBouncer(bouncerName string, bouncers []*ent.Bouncer) (string, error) {
	bouncerPrefix := strings.Split(bouncerName, "@")[0]
	for _, bouncer := range bouncers {
		if strings.HasPrefix(bouncer.Name, bouncerPrefix) && !bouncer.AutoCreated {
			return bouncer.Name, nil
		}
	}

	return "", errors.New("no parent bouncer found")
}

func (cli *cliBouncers) delete(ctx context.Context, bouncers []string, ignoreMissing bool) error {
	allBouncers, err := cli.db.ListBouncers(ctx)
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %w", err)
	}
	for _, bouncerName := range bouncers {
		bouncer, err := cli.db.SelectBouncerByName(ctx, bouncerName)
		if err != nil {
			var notFoundErr *ent.NotFoundError
			if ignoreMissing && errors.As(err, &notFoundErr) {
				continue
			}
			return fmt.Errorf("unable to delete bouncer %s: %w", bouncerName, err)
		}

		// For TLS bouncers, always delete them, they have no parents
		if bouncer.AuthType == types.TlsAuthType {
			if err := cli.db.DeleteBouncer(ctx, bouncerName); err != nil {
				return fmt.Errorf("unable to delete bouncer %s: %w", bouncerName, err)
			}
			continue
		}

		if bouncer.AutoCreated {
			parentBouncer, err := cli.findParentBouncer(bouncerName, allBouncers)
			if err != nil {
				log.Errorf("bouncer '%s' is auto-created, but couldn't find a parent bouncer", err)
				continue
			}
			log.Warnf("bouncer '%s' is auto-created and cannot be deleted, delete parent bouncer %s instead", bouncerName, parentBouncer)
			continue
		}
		//Try to find all child bouncers and delete them
		for _, childBouncer := range allBouncers {
			if strings.HasPrefix(childBouncer.Name, bouncerName+"@") && childBouncer.AutoCreated {
				if err := cli.db.DeleteBouncer(ctx, childBouncer.Name); err != nil {
					return fmt.Errorf("unable to delete bouncer %s: %w", childBouncer.Name, err)
				}
				log.Infof("bouncer '%s' deleted successfully", childBouncer.Name)
			}
		}

		if err := cli.db.DeleteBouncer(ctx, bouncerName); err != nil {
			return fmt.Errorf("unable to delete bouncer %s: %w", bouncerName, err)
		}

		log.Infof("bouncer '%s' deleted successfully", bouncerName)
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
