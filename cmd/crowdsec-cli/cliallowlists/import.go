package cliallowlists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/jszwec/csvutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/require"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type allowlistItemRaw struct {
	Value      string `csv:"value"`
	Expiration string `csv:"expiration,omitempty"`
	Comment    string `csv:"comment,omitempty"`
}

func (cli *cliAllowLists) newImportCmd() *cobra.Command {
	var input string

	cmd := &cobra.Command{
		Use:   "import [allowlist_name] -i <file>",
		Short: "Import values to an allowlist from a CSV file",
		Long: "Import values to an allowlist from a CSV file.\n\n" +
			"The CSV file must have a header line with at least a 'value' column.\n" +
			"Optional columns: 'expiration' (duration like 1h, 1d), 'comment'.",
		Example: `csv file:
value,expiration,comment
1.2.3.4,24h,my comment
2.3.4.5,,another comment
10.0.0.0/8,1d,

$ cscli allowlists import my_allowlist -i allowlist.csv

From standard input:

$ cat allowlist.csv | cscli allowlists import my_allowlist -i -`,
		Args:              args.ExactArgs(1),
		ValidArgsFunction: cli.validAllowlists,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := cli.cfg()

			if err := require.LAPI(cfg); err != nil {
				return err
			}

			ctx := cmd.Context()

			db, err := require.DBClient(ctx, cfg.DbConfig)
			if err != nil {
				return err
			}

			name := args[0]

			return cli.import_(ctx, db, name, input)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&input, "input", "i", "", "Input file (use - for stdin)")

	_ = cmd.MarkFlagRequired("input")

	return cmd
}

func (*cliAllowLists) import_(ctx context.Context, db *database.Client, name string, input string) error {
	var (
		fin *os.File
		err error
	)

	if input == "-" {
		fin = os.Stdin
	} else {
		fin, err = os.Open(input)
		if err != nil {
			return fmt.Errorf("unable to open %s: %w", input, err)
		}
		defer fin.Close()
	}

	content, err := io.ReadAll(fin)
	if err != nil {
		return fmt.Errorf("unable to read from %s: %w", input, err)
	}

	var items []allowlistItemRaw

	if err := csvutil.Unmarshal(content, &items); err != nil {
		return fmt.Errorf("unable to parse CSV: %w", err)
	}

	if len(items) == 0 {
		return errors.New("no values to import")
	}

	allowlist, err := db.GetAllowList(ctx, name, true)
	if err != nil {
		return err
	}

	if allowlist.FromConsole {
		return fmt.Errorf("allowlist %s is managed by console, cannot update with cscli. Please visit https://app.crowdsec.net/allowlists/%s to update", name, allowlist.AllowlistID)
	}

	toAdd := make([]*models.AllowlistItem, 0)

	for i, item := range items {
		if item.Value == "" {
			return fmt.Errorf("row %d: missing 'value'", i+1)
		}

		found := false

		for _, existing := range allowlist.Edges.AllowlistItems {
			if existing.Value == item.Value {
				found = true

				log.Warnf("value %s already in allowlist", item.Value)

				break
			}
		}

		if found {
			continue
		}

		expTS := time.Time{}

		if item.Expiration != "" {
			duration, err := cstime.ParseDurationWithDays(item.Expiration)
			if err != nil {
				return fmt.Errorf("row %d: invalid expiration %q: %w", i+1, item.Expiration, err)
			}

			expTS = time.Now().UTC().Add(duration)
		}

		toAdd = append(toAdd, &models.AllowlistItem{
			Value:       item.Value,
			Description: item.Comment,
			Expiration:  strfmt.DateTime(expTS),
		})
	}

	if len(toAdd) == 0 {
		fmt.Fprintln(os.Stdout, "no new values for allowlist")
		return nil
	}

	added, err := db.AddToAllowlist(ctx, allowlist, toAdd)
	if err != nil {
		return fmt.Errorf("unable to add values to allowlist: %w", err)
	}

	if added > 0 {
		fmt.Fprintf(os.Stdout, "added %d values to allowlist %s\n", added, name)
	}

	deleted, err := db.ApplyAllowlistsToExistingDecisions(ctx)
	if err != nil {
		return fmt.Errorf("unable to apply allowlists to existing decisions: %w", err)
	}

	if deleted > 0 {
		fmt.Fprintf(os.Stdout, "%d decisions deleted by allowlists\n", deleted)
	}

	return nil
}
