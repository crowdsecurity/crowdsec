package climachine

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/ask"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/idgen"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

type configGetter = func() *csconfig.Config

type cliMachines struct {
	db  *database.Client
	cfg configGetter
}

func New(cfg configGetter) *cliMachines {
	return &cliMachines{
		cfg: cfg,
	}
}

func (cli *cliMachines) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines [requires local API]",
		Long: `To list/add/delete/validate/prune machines.
Note: This command requires database direct access, so is intended to be run on the local API machine.
`,
		Example:           `cscli machines [action]`,
		DisableAutoGenTag: true,
		Aliases:           []string{"machine"},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if err = require.LAPI(cli.cfg()); err != nil {
				return err
			}
			cli.db, err = require.DBClient(cmd.Context(), cli.cfg().DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newValidateCmd())
	cmd.AddCommand(cli.newPruneCmd())
	cmd.AddCommand(cli.newInspectCmd())

	return cmd
}

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
		io.WriteString(out, t.Render()+"\n")
	}
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

	io.WriteString(out, t.Render()+"\n")
}

// machineInfo contains only the data we want for inspect/list: no hub status, scenarios, edges, etc.
type machineInfo struct {
	CreatedAt     time.Time        `json:"created_at,omitempty"`
	UpdatedAt     time.Time        `json:"updated_at,omitempty"`
	LastPush      *time.Time       `json:"last_push,omitempty"`
	LastHeartbeat *time.Time       `json:"last_heartbeat,omitempty"`
	MachineId     string           `json:"machineId,omitempty"`
	IpAddress     string           `json:"ipAddress,omitempty"`
	Version       string           `json:"version,omitempty"`
	IsValidated   bool             `json:"isValidated,omitempty"`
	AuthType      string           `json:"auth_type"`
	OS            string           `json:"os,omitempty"`
	Featureflags  []string         `json:"featureflags,omitempty"`
	Datasources   map[string]int64 `json:"datasources,omitempty"`
}

func newMachineInfo(m *ent.Machine) machineInfo {
	return machineInfo{
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
		LastPush:      m.LastPush,
		LastHeartbeat: m.LastHeartbeat,
		MachineId:     m.MachineId,
		IpAddress:     m.IpAddress,
		Version:       m.Version,
		IsValidated:   m.IsValidated,
		AuthType:      m.AuthType,
		OS:            clientinfo.GetOSNameAndVersion(m),
		Featureflags:  clientinfo.GetFeatureFlagList(m),
		Datasources:   m.Datasources,
	}
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

func (cli *cliMachines) List(out io.Writer, db *database.Client) error {
	// XXX: must use the provided db object, the one in the struct might be nil
	// (calling List directly skips the PersistentPreRunE)

	machines, err := db.ListMachines()
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.List(color.Output, cli.db)
		},
	}

	return cmd
}

func (cli *cliMachines) newAddCmd() *cobra.Command {
	var (
		password    MachinePassword
		dumpFile    string
		apiURL      string
		interactive bool
		autoAdd     bool
		force       bool
	)

	cmd := &cobra.Command{
		Use:               "add",
		Short:             "add a single machine to the database",
		DisableAutoGenTag: true,
		Long:              `Register a new machine in the database. cscli should be on the same machine as LAPI.`,
		Example: `cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword
cscli machines add -f- --auto > /tmp/mycreds.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.add(cmd.Context(), args, string(password), dumpFile, apiURL, interactive, autoAdd, force)
		},
	}

	flags := cmd.Flags()
	flags.VarP(&password, "password", "p", "machine password to login to the API")
	flags.StringVarP(&dumpFile, "file", "f", "", "output file destination (defaults to "+csconfig.DefaultConfigPath("local_api_credentials.yaml")+")")
	flags.StringVarP(&apiURL, "url", "u", "", "URL of the local API")
	flags.BoolVarP(&interactive, "interactive", "i", false, "interfactive mode to enter the password")
	flags.BoolVarP(&autoAdd, "auto", "a", false, "automatically generate password (and username if not provided)")
	flags.BoolVar(&force, "force", false, "will force add the machine if it already exist")

	return cmd
}

func (cli *cliMachines) add(ctx context.Context, args []string, machinePassword string, dumpFile string, apiURL string, interactive bool, autoAdd bool, force bool) error {
	var (
		err       error
		machineID string
	)

	// create machineID if not specified by user
	if len(args) == 0 {
		if !autoAdd {
			return errors.New("please specify a machine name to add, or use --auto")
		}

		machineID, err = idgen.GenerateMachineID("")
		if err != nil {
			return fmt.Errorf("unable to generate machine id: %w", err)
		}
	} else {
		machineID = args[0]
	}

	clientCfg := cli.cfg().API.Client
	serverCfg := cli.cfg().API.Server

	/*check if file already exists*/
	if dumpFile == "" && clientCfg != nil && clientCfg.CredentialsFilePath != "" {
		credFile := clientCfg.CredentialsFilePath
		// use the default only if the file does not exist
		_, err = os.Stat(credFile)

		switch {
		case os.IsNotExist(err) || force:
			dumpFile = credFile
		case err != nil:
			return fmt.Errorf("unable to stat '%s': %w", credFile, err)
		default:
			return fmt.Errorf(`credentials file '%s' already exists: please remove it, use "--force" or specify a different file with "-f" ("-f -" for standard output)`, credFile)
		}
	}

	if dumpFile == "" {
		return errors.New(`please specify a file to dump credentials to, with -f ("-f -" for standard output)`)
	}

	// create a password if it's not specified by user
	if machinePassword == "" && !interactive {
		if !autoAdd {
			return errors.New("please specify a password with --password or use --auto")
		}

		machinePassword = idgen.GeneratePassword(idgen.PasswordLength)
	} else if machinePassword == "" && interactive {
		qs := &survey.Password{
			Message: "Please provide a password for the machine:",
		}
		survey.AskOne(qs, &machinePassword)
	}

	password := strfmt.Password(machinePassword)

	_, err = cli.db.CreateMachine(ctx, &machineID, &password, "", true, force, types.PasswordAuthType)
	if err != nil {
		return fmt.Errorf("unable to create machine: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Machine '%s' successfully added to the local API.\n", machineID)

	if apiURL == "" {
		if clientCfg != nil && clientCfg.Credentials != nil && clientCfg.Credentials.URL != "" {
			apiURL = clientCfg.Credentials.URL
		} else if serverCfg.ClientURL() != "" {
			apiURL = serverCfg.ClientURL()
		} else {
			return errors.New("unable to dump an api URL. Please provide it in your configuration or with the -u parameter")
		}
	}

	apiCfg := csconfig.ApiCredentialsCfg{
		Login:    machineID,
		Password: password.String(),
		URL:      apiURL,
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to serialize api credentials: %w", err)
	}

	if dumpFile != "" && dumpFile != "-" {
		if err = os.WriteFile(dumpFile, apiConfigDump, 0o600); err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %w", dumpFile, err)
		}

		fmt.Fprintf(os.Stderr, "API credentials written to '%s'.\n", dumpFile)
	} else {
		fmt.Print(string(apiConfigDump))
	}

	return nil
}

// validMachineID returns a list of machine IDs for command completion
func (cli *cliMachines) validMachineID(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error

	cfg := cli.cfg()

	// need to load config and db because PersistentPreRunE is not called for completions

	if err = require.LAPI(cfg); err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cli.db, err = require.DBClient(cmd.Context(), cfg.DbConfig)
	if err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	machines, err := cli.db.ListMachines()
	if err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ret := []string{}

	for _, machine := range machines {
		if strings.Contains(machine.MachineId, toComplete) && !slices.Contains(args, machine.MachineId) {
			ret = append(ret, machine.MachineId)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

func (cli *cliMachines) delete(machines []string, ignoreMissing bool) error {
	for _, machineID := range machines {
		if err := cli.db.DeleteWatcher(machineID); err != nil {
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
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.delete(args, ignoreMissing)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&ignoreMissing, "ignore-missing", false, "don't print errors if one or more machines don't exist")

	return cmd
}

func (cli *cliMachines) prune(duration time.Duration, notValidOnly bool, force bool) error {
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
	if pending, err := cli.db.QueryPendingMachine(); err == nil {
		machines = append(machines, pending...)
	}

	if !notValidOnly {
		if pending, err := cli.db.QueryMachinesInactiveSince(time.Now().UTC().Add(-duration)); err == nil {
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

	deleted, err := cli.db.BulkDeleteWatchers(machines)
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.prune(duration, notValidOnly, force)
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", defaultDuration, "duration of time since validated machine last heartbeat")
	flags.BoolVar(&notValidOnly, "not-validated-only", false, "only prune machines that are not validated")
	flags.BoolVar(&force, "force", false, "force prune without asking for confirmation")

	return cmd
}

func (cli *cliMachines) validate(machineID string) error {
	if err := cli.db.ValidateMachine(machineID); err != nil {
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
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.validate(args[0])
		},
	}

	return cmd
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

	io.WriteString(out, t.Render()+"\n")
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
