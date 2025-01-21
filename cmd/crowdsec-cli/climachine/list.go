package climachine

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

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// getLastHeartbeat returns the last heartbeat timestamp of a machine
// and a boolean indicating if the machine is considered active or not.
func getLastHeartbeat(m *ent.Machine) (string, bool) {
	if m.LastHeartbeat == nil {
		return "-", false
	}

	elapsed := time.Now().UTC().Sub(*m.LastHeartbeat)

	hb := elapsed.Truncate(time.Second).String()
	if elapsed > 2*time.Minute {
		return hb, false
	}

	return hb, true
}

func (cli *cliMachines) listHuman(out io.Writer, machines ent.Machines) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Name", "IP Address", "Last Update", "Status", "Version", "OS", "Auth Type", "Last Heartbeat"})

	for _, m := range machines {
		validated := emoji.Prohibited
		if m.IsValidated {
			validated = emoji.CheckMark
		}

		hb, active := getLastHeartbeat(m)
		if !active {
			hb = emoji.Warning + " " + hb
		}

		t.AppendRow(table.Row{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, clientinfo.GetOSNameAndVersion(m), m.AuthType, hb})
	}

	fmt.Fprintln(out, t.Render())
}

func (cli *cliMachines) listCSV(out io.Writer, machines ent.Machines) error {
	csvwriter := csv.NewWriter(out)

	err := csvwriter.Write([]string{"machine_id", "ip_address", "updated_at", "validated", "version", "auth_type", "last_heartbeat", "os"})
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, m := range machines {
		validated := "false"
		if m.IsValidated {
			validated = "true"
		}

		hb := "-"
		if m.LastHeartbeat != nil {
			hb = m.LastHeartbeat.Format(time.RFC3339)
		}

		if err := csvwriter.Write([]string{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, hb, fmt.Sprintf("%s/%s", m.Osname, m.Osversion)}); err != nil {
			return fmt.Errorf("failed to write raw output: %w", err)
		}
	}

	csvwriter.Flush()

	return nil
}

func (cli *cliMachines) List(ctx context.Context, out io.Writer, db *database.Client) error {
	// XXX: must use the provided db object, the one in the struct might be nil
	// (calling List directly skips the PersistentPreRunE)
	machines, err := db.ListMachines(ctx)
	if err != nil {
		return fmt.Errorf("unable to list machines: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		cli.listHuman(out, machines)
	case "json":
		info := make([]machineInfo, 0, len(machines))
		for _, m := range machines {
			info = append(info, newMachineInfo(m))
		}

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(info); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		return cli.listCSV(out, machines)
	}

	return nil
}

func (cli *cliMachines) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list all machines in the database",
		Long:              `list all machines in the database with their status and last heartbeat`,
		Example:           `cscli machines list`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.List(cmd.Context(), color.Output, cli.db)
		},
	}

	return cmd
}
