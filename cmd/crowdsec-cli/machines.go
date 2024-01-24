package main

import (
	saferand "crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"slices"

	"github.com/crowdsecurity/machineid"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const passwordLength = 64

func generatePassword(length int) string {
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"

	charset := upper + lower + digits
	charsetLength := len(charset)

	buf := make([]byte, length)

	for i := 0; i < length; i++ {
		rInt, err := saferand.Int(saferand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			log.Fatalf("failed getting data from prng for password generation : %s", err)
		}
		buf[i] = charset[rInt.Int64()]
	}

	return string(buf)
}

// Returns a unique identifier for each crowdsec installation, using an
// identifier of the OS installation where available, otherwise a random
// string.
func generateIDPrefix() (string, error) {
	prefix, err := machineid.ID()
	if err == nil {
		return prefix, nil
	}
	log.Debugf("failed to get machine-id with usual files: %s", err)

	bID, err := uuid.NewRandom()
	if err == nil {
		return bID.String(), nil
	}
	return "", fmt.Errorf("generating machine id: %w", err)
}

// Generate a unique identifier, composed by a prefix and a random suffix.
// The prefix can be provided by a parameter to use in test environments.
func generateID(prefix string) (string, error) {
	var err error
	if prefix == "" {
		prefix, err = generateIDPrefix()
	}
	if err != nil {
		return "", err
	}
	prefix = strings.ReplaceAll(prefix, "-", "")[:32]
	suffix := generatePassword(16)
	return prefix + suffix, nil
}

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

type cliMachines struct{
	db *database.Client
	cfg func() *csconfig.Config
}

func NewCLIMachines(getconfig func() *csconfig.Config) *cliMachines {
	return &cliMachines{
		cfg: getconfig,
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
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			var err error
			if err = require.LAPI(cli.cfg()); err != nil {
				return err
			}
			cli.db, err = database.NewClient(cli.cfg().DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}
			return nil
		},
	}

	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewAddCmd())
	cmd.AddCommand(cli.NewDeleteCmd())
	cmd.AddCommand(cli.NewValidateCmd())
	cmd.AddCommand(cli.NewPruneCmd())

	return cmd
}

func (cli *cliMachines) list() error {
	out := color.Output

	machines, err := cli.db.ListMachines()
	if err != nil {
		return fmt.Errorf("unable to list machines: %s", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		getAgentsTable(out, machines)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(machines); err != nil {
			return fmt.Errorf("failed to marshal")
		}

		return nil
	case "raw":
		csvwriter := csv.NewWriter(out)

		err := csvwriter.Write([]string{"machine_id", "ip_address", "updated_at", "validated", "version", "auth_type", "last_heartbeat"})
		if err != nil {
			return fmt.Errorf("failed to write header: %s", err)
		}

		for _, m := range machines {
			validated := "false"
			if m.IsValidated {
				validated = "true"
			}

			hb, _ := getLastHeartbeat(m)

			if err := csvwriter.Write([]string{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, hb}); err != nil {
				return fmt.Errorf("failed to write raw output: %w", err)
			}
		}

		csvwriter.Flush()
	default:
		return fmt.Errorf("unknown output '%s'", cli.cfg().Cscli.Output)
	}

	return nil
}

func (cli *cliMachines) NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list all machines in the database",
		Long:              `list all machines in the database with their status and last heartbeat`,
		Example:           `cscli machines list`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.list()
		},
	}

	return cmd
}

func (cli *cliMachines) NewAddCmd() *cobra.Command {
	var (
		machinePassword    string
		dumpFile           string
		apiURL             string
		interactive        bool
		autoAdd            bool
		force              bool
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
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.add(args, machinePassword, dumpFile, apiURL, interactive, autoAdd, force)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&machinePassword, "password", "p", "", "machine password to login to the API")
	flags.StringVarP(&dumpFile, "file", "f", "", "output file destination (defaults to "+csconfig.DefaultConfigPath("local_api_credentials.yaml")+")")
	flags.StringVarP(&apiURL, "url", "u", "", "URL of the local API")
	flags.BoolVarP(&interactive, "interactive", "i", false, "interfactive mode to enter the password")
	flags.BoolVarP(&autoAdd, "auto", "a", false, "automatically generate password (and username if not provided)")
	flags.BoolVar(&force, "force", false, "will force add the machine if it already exist")

	return cmd
}

func (cli *cliMachines) add(args []string, machinePassword string, dumpFile string, apiURL string, interactive bool, autoAdd bool, force bool) error {
	var (
		err error
		machineID string
	)

	// create machineID if not specified by user
	if len(args) == 0 {
		if !autoAdd {
			return fmt.Errorf("please specify a machine name to add, or use --auto")
		}

		machineID, err = generateID("")
		if err != nil {
			return fmt.Errorf("unable to generate machine id: %s", err)
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
			return fmt.Errorf("unable to stat '%s': %s", credFile, err)
		default:
			return fmt.Errorf(`credentials file '%s' already exists: please remove it, use "--force" or specify a different file with "-f" ("-f -" for standard output)`, credFile)
		}
	}

	if dumpFile == "" {
		return fmt.Errorf(`please specify a file to dump credentials to, with -f ("-f -" for standard output)`)
	}

	// create a password if it's not specified by user
	if machinePassword == "" && !interactive {
		if !autoAdd {
			return fmt.Errorf("please specify a password with --password or use --auto")
		}
		machinePassword = generatePassword(passwordLength)
	} else if machinePassword == "" && interactive {
		qs := &survey.Password{
			Message: "Please provide a password for the machine:",
		}
		survey.AskOne(qs, &machinePassword)
	}

	password := strfmt.Password(machinePassword)

	_, err = cli.db.CreateMachine(&machineID, &password, "", true, force, types.PasswordAuthType)
	if err != nil {
		return fmt.Errorf("unable to create machine: %s", err)
	}

	fmt.Fprintf(os.Stderr, "Machine '%s' successfully added to the local API.\n", machineID)

	if apiURL == "" {
		if clientCfg != nil && clientCfg.Credentials != nil && clientCfg.Credentials.URL != "" {
			apiURL = clientCfg.Credentials.URL
		} else if serverCfg != nil && serverCfg.ListenURI != "" {
			apiURL = "http://" + serverCfg.ListenURI
		} else {
			return fmt.Errorf("unable to dump an api URL. Please provide it in your configuration or with the -u parameter")
		}
	}

	apiCfg := csconfig.ApiCredentialsCfg{
		Login:    machineID,
		Password: password.String(),
		URL:      apiURL,
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to marshal api credentials: %s", err)
	}

	if dumpFile != "" && dumpFile != "-" {
		err = os.WriteFile(dumpFile, apiConfigDump, 0o600)
		if err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %s", dumpFile, err)
		}
		fmt.Fprintf(os.Stderr, "API credentials written to '%s'.\n", dumpFile)
	} else {
		fmt.Print(string(apiConfigDump))
	}

	return nil
}

func (cli *cliMachines) deleteValid(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	machines, err := cli.db.ListMachines()
	if err != nil {
		cobra.CompError("unable to list machines " + err.Error())
	}

	ret := []string{}

	for _, machine := range machines {
		if strings.Contains(machine.MachineId, toComplete) && !slices.Contains(args, machine.MachineId) {
			ret = append(ret, machine.MachineId)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

func (cli *cliMachines) delete(machines []string) error {
	for _, machineID := range machines {
		err := cli.db.DeleteWatcher(machineID)
		if err != nil {
			log.Errorf("unable to delete machine '%s': %s", machineID, err)
			return nil
		}
		log.Infof("machine '%s' deleted successfully", machineID)
	}

	return nil
}

func (cli *cliMachines) NewDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "delete [machine_name]...",
		Short:             "delete machine(s) by name",
		Example:           `cscli machines delete "machine1" "machine2"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.deleteValid,
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.delete(args)
		},
	}

	return cmd
}

func (cli *cliMachines) prune(duration time.Duration, notValidOnly bool, force bool) error {
	if duration < 2*time.Minute && !notValidOnly {
		if yes, err := askYesNo(
				"The duration you provided is less than 2 minutes. " +
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
		if pending, err := cli.db.QueryLastValidatedHeartbeatLT(time.Now().UTC().Add(duration)); err == nil {
			machines = append(machines, pending...)
		}
	}

	if len(machines) == 0 {
		fmt.Println("no machines to prune")
		return nil
	}

	getAgentsTable(color.Output, machines)

	if !force {
		if yes, err := askYesNo(
				"You are about to PERMANENTLY remove the above machines from the database. " +
				"These will NOT be recoverable. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	deleted, err := cli.db.BulkDeleteWatchers(machines)
	if err != nil {
		return fmt.Errorf("unable to prune machines: %s", err)
	}

	fmt.Fprintf(os.Stderr, "successfully delete %d machines\n", deleted)

	return nil
}

func (cli *cliMachines) NewPruneCmd() *cobra.Command {
	var (
		duration       time.Duration
		notValidOnly   bool
		force          bool
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
		return fmt.Errorf("unable to validate machine '%s': %s", machineID, err)
	}
	log.Infof("machine '%s' validated successfully", machineID)

	return nil
}

func (cli *cliMachines) NewValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "validate",
		Short:             "validate a machine to access the local API",
		Long:              `validate a machine to access the local API.`,
		Example:           `cscli machines validate "machine_name"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.validate(args[0])
		},
	}

	return cmd
}
