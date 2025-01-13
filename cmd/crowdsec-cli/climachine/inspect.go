package climachine

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func (cli *cliMachines) inspectHubHuman(out io.Writer, machine *ent.Machine) {
	state := machine.Hubstate

	if len(state) == 0 {
		fmt.Println("No hub items found for this machine")
		return
	}

	// group state rows by type for multiple tables
	rowsByType := make(map[string][]table.Row)

	for itemType, items := range state {
		for _, item := range items {
			if _, ok := rowsByType[itemType]; !ok {
				rowsByType[itemType] = make([]table.Row, 0)
			}

			row := table.Row{item.Name, item.Status, item.Version}
			rowsByType[itemType] = append(rowsByType[itemType], row)
		}
	}

	for itemType, rows := range rowsByType {
		t := cstable.New(out, cli.cfg().Cscli.Color).Writer
		t.AppendHeader(table.Row{"Name", "Status", "Version"})
		t.SetTitle(itemType)
		t.AppendRows(rows)
		fmt.Fprintln(out, t.Render())
	}
}

func (cli *cliMachines) inspectHuman(out io.Writer, machine *ent.Machine) {
	t := cstable.New(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Machine: " + machine.MachineId)

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	t.AppendRows([]table.Row{
		{"IP Address", machine.IpAddress},
		{"Created At", machine.CreatedAt},
		{"Last Update", machine.UpdatedAt},
		{"Last Heartbeat", machine.LastHeartbeat},
		{"Validated?", machine.IsValidated},
		{"CrowdSec version", machine.Version},
		{"OS", clientinfo.GetOSNameAndVersion(machine)},
		{"Auth type", machine.AuthType},
	})

	for dsName, dsCount := range machine.Datasources {
		t.AppendRow(table.Row{"Datasources", fmt.Sprintf("%s: %d", dsName, dsCount)})
	}

	for _, ff := range clientinfo.GetFeatureFlagList(machine) {
		t.AppendRow(table.Row{"Feature Flags", ff})
	}

	for _, coll := range machine.Hubstate[cwhub.COLLECTIONS] {
		t.AppendRow(table.Row{"Collections", coll.Name})
	}

	fmt.Fprintln(out, t.Render())
}

func (cli *cliMachines) inspect(machine *ent.Machine) error {
	out := color.Output
	outputFormat := cli.cfg().Cscli.Output

	switch outputFormat {
	case "human":
		cli.inspectHuman(out, machine)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(newMachineInfo(machine)); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}

func (cli *cliMachines) inspectHub(machine *ent.Machine) error {
	out := color.Output

	switch cli.cfg().Cscli.Output {
	case "human":
		cli.inspectHubHuman(out, machine)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(machine.Hubstate); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		csvwriter := csv.NewWriter(out)

		err := csvwriter.Write([]string{"type", "name", "status", "version"})
		if err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}

		rows := make([][]string, 0)

		for itemType, items := range machine.Hubstate {
			for _, item := range items {
				rows = append(rows, []string{itemType, item.Name, item.Status, item.Version})
			}
		}

		for _, row := range rows {
			if err := csvwriter.Write(row); err != nil {
				return fmt.Errorf("failed to write raw output: %w", err)
			}
		}

		csvwriter.Flush()
	}

	return nil
}

func (cli *cliMachines) newInspectCmd() *cobra.Command {
	var showHub bool

	cmd := &cobra.Command{
		Use:               "inspect [machine_name]",
		Short:             "inspect a machine by name",
		Example:           `cscli machines inspect "machine1"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validMachineID,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			machineID := args[0]

			machine, err := cli.db.QueryMachineByID(ctx, machineID)
			if err != nil {
				return fmt.Errorf("unable to read machine data '%s': %w", machineID, err)
			}

			if showHub {
				return cli.inspectHub(machine)
			}

			return cli.inspect(machine)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&showHub, "hub", "H", false, "show hub state")

	return cmd
}
