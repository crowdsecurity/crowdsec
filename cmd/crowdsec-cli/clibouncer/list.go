package clibouncer

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func (cli *cliBouncers) listHuman(out io.Writer, bouncers ent.Bouncers) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Name", "IP Address", "Valid", "Last API pull", "Type", "Version", "Auth Type"})

	for _, b := range bouncers {
		revoked := emoji.CheckMark
		if b.Revoked {
			revoked = emoji.Prohibited
		}

		lastPull := ""
		if b.LastPull != nil {
			lastPull = b.LastPull.Format(time.RFC3339)
		}

		t.AppendRow(table.Row{b.Name, b.IPAddress, revoked, lastPull, b.Type, b.Version, b.AuthType})
	}

	fmt.Fprintln(out, t.Render())
}

func (cli *cliBouncers) listCSV(out io.Writer, bouncers ent.Bouncers) error {
	csvwriter := csv.NewWriter(out)

	if err := csvwriter.Write([]string{"name", "ip", "revoked", "last_pull", "type", "version", "auth_type"}); err != nil {
		return fmt.Errorf("failed to write raw header: %w", err)
	}

	for _, b := range bouncers {
		valid := "validated"
		if b.Revoked {
			valid = "pending"
		}

		lastPull := ""
		if b.LastPull != nil {
			lastPull = b.LastPull.Format(time.RFC3339)
		}

		if err := csvwriter.Write([]string{b.Name, b.IPAddress, valid, lastPull, b.Type, b.Version, b.AuthType}); err != nil {
			return fmt.Errorf("failed to write raw: %w", err)
		}
	}

	csvwriter.Flush()

	return nil
}

func (cli *cliBouncers) List(ctx context.Context, out io.Writer, db *database.Client) error {
	// XXX: must use the provided db object, the one in the struct might be nil
	// (calling List directly skips the PersistentPreRunE)
	bouncers, err := db.ListBouncers(ctx)
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		cli.listHuman(out, bouncers)
	case "json":
		info := make([]bouncerInfo, 0, len(bouncers))
		for _, b := range bouncers {
			info = append(info, newBouncerInfo(b))
		}

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(info); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		return cli.listCSV(out, bouncers)
	}

	return nil
}

func (cli *cliBouncers) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list all bouncers within the database",
		Example:           `cscli bouncers list`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.List(cmd.Context(), color.Output, cli.db)
		},
	}

	return cmd
}
