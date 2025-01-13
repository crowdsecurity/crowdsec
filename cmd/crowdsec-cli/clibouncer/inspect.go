package clibouncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
)

func (cli *cliBouncers) inspectHuman(out io.Writer, bouncer *ent.Bouncer) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Bouncer: " + bouncer.Name)

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	lastPull := ""
	if bouncer.LastPull != nil {
		lastPull = bouncer.LastPull.String()
	}

	t.AppendRows([]table.Row{
		{"Created At", bouncer.CreatedAt},
		{"Last Update", bouncer.UpdatedAt},
		{"Revoked?", bouncer.Revoked},
		{"IP Address", bouncer.IPAddress},
		{"Type", bouncer.Type},
		{"Version", bouncer.Version},
		{"Last Pull", lastPull},
		{"Auth type", bouncer.AuthType},
		{"OS", clientinfo.GetOSNameAndVersion(bouncer)},
		{"Auto Created", bouncer.AutoCreated},
	})

	for _, ff := range clientinfo.GetFeatureFlagList(bouncer) {
		t.AppendRow(table.Row{"Feature Flags", ff})
	}

	fmt.Fprint(out, t.Render())
}

func (cli *cliBouncers) inspect(bouncer *ent.Bouncer) error {
	out := color.Output
	outputFormat := cli.cfg().Cscli.Output

	switch outputFormat {
	case "human":
		cli.inspectHuman(out, bouncer)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(newBouncerInfo(bouncer)); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}

func (cli *cliBouncers) newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "inspect [bouncer_name]",
		Short:             "inspect a bouncer by name",
		Example:           `cscli bouncers inspect "bouncer1"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validBouncerID,
		RunE: func(cmd *cobra.Command, args []string) error {
			bouncerName := args[0]

			b, err := cli.db.Ent.Bouncer.Query().
				Where(bouncer.Name(bouncerName)).
				Only(cmd.Context())
			if err != nil {
				return fmt.Errorf("unable to read bouncer data '%s': %w", bouncerName, err)
			}

			return cli.inspect(b)
		},
	}

	return cmd
}
