package main

import (
	saferand "crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/machineid"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var (
	passwordLength = 64
)

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

	bId, err := uuid.NewRandom()
	if err == nil {
		return bId.String(), nil
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

func getAgents(out io.Writer, dbClient *database.Client) error {
	machines, err := dbClient.ListMachines()
	if err != nil {
		return fmt.Errorf("unable to list machines: %s", err)
	}
	if csConfig.Cscli.Output == "human" {
		getAgentsTable(out, machines)
	} else if csConfig.Cscli.Output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(machines); err != nil {
			return fmt.Errorf("failed to marshal")
		}
		return nil
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		err := csvwriter.Write([]string{"machine_id", "ip_address", "updated_at", "validated", "version", "auth_type", "last_heartbeat"})
		if err != nil {
			return fmt.Errorf("failed to write header: %s", err)
		}
		for _, m := range machines {
			var validated string
			if m.IsValidated {
				validated = "true"
			} else {
				validated = "false"
			}
			hb, _ := getLastHeartbeat(m)
			err := csvwriter.Write([]string{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, hb})
			if err != nil {
				return fmt.Errorf("failed to write raw output: %w", err)
			}
		}
		csvwriter.Flush()
	} else {
		log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
	}
	return nil
}

func NewMachinesListCmd() *cobra.Command {
	cmdMachinesList := &cobra.Command{
		Use:               "list",
		Short:             "List machines",
		Long:              `List `,
		Example:           `cscli machines list`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := getAgents(color.Output, dbClient)
			if err != nil {
				return fmt.Errorf("unable to list machines: %s", err)
			}

			return nil
		},
	}

	return cmdMachinesList
}

func NewMachinesAddCmd() *cobra.Command {
	cmdMachinesAdd := &cobra.Command{
		Use:               "add",
		Short:             "add machine to the database.",
		DisableAutoGenTag: true,
		Long:              `Register a new machine in the database. cscli should be on the same machine as LAPI.`,
		Example: `
cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}

			return nil
		},
		RunE: runMachinesAdd,
	}

	flags := cmdMachinesAdd.Flags()
	flags.StringP("password", "p", "", "machine password to login to the API")
	flags.StringP("file", "f", "", "output file destination (defaults to "+csconfig.DefaultConfigPath("local_api_credentials.yaml")+")")
	flags.StringP("url", "u", "", "URL of the local API")
	flags.BoolP("interactive", "i", false, "interfactive mode to enter the password")
	flags.BoolP("auto", "a", false, "automatically generate password (and username if not provided)")
	flags.Bool("force", false, "will force add the machine if it already exist")

	return cmdMachinesAdd
}

func runMachinesAdd(cmd *cobra.Command, args []string) error {
	var dumpFile string
	var err error

	flags := cmd.Flags()

	machinePassword, err := flags.GetString("password")
	if err != nil {
		return err
	}

	outputFile, err := flags.GetString("file")
	if err != nil {
		return err
	}

	apiURL, err := flags.GetString("url")
	if err != nil {
		return err
	}

	interactive, err := flags.GetBool("interactive")
	if err != nil {
		return err
	}

	autoAdd, err := flags.GetBool("auto")
	if err != nil {
		return err
	}

	forceAdd, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	var machineID string

	// create machineID if not specified by user
	if len(args) == 0 {
		if !autoAdd {
			printHelp(cmd)
			return nil
		}
		machineID, err = generateID("")
		if err != nil {
			return fmt.Errorf("unable to generate machine id: %s", err)
		}
	} else {
		machineID = args[0]
	}

	/*check if file already exists*/
	if outputFile != "" {
		dumpFile = outputFile
	} else if csConfig.API.Client != nil && csConfig.API.Client.CredentialsFilePath != "" {
		dumpFile = csConfig.API.Client.CredentialsFilePath
	}

	// create a password if it's not specified by user
	if machinePassword == "" && !interactive {
		if !autoAdd {
			printHelp(cmd)
			return nil
		}
		machinePassword = generatePassword(passwordLength)
	} else if machinePassword == "" && interactive {
		qs := &survey.Password{
			Message: "Please provide a password for the machine",
		}
		survey.AskOne(qs, &machinePassword)
	}
	password := strfmt.Password(machinePassword)
	_, err = dbClient.CreateMachine(&machineID, &password, "", true, forceAdd, types.PasswordAuthType)
	if err != nil {
		return fmt.Errorf("unable to create machine: %s", err)
	}
	log.Infof("Machine '%s' successfully added to the local API", machineID)

	if apiURL == "" {
		if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
			apiURL = csConfig.API.Client.Credentials.URL
		} else if csConfig.API.Server != nil && csConfig.API.Server.ListenURI != "" {
			apiURL = csConfig.API.Server.ClientUrl()
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
		err = os.WriteFile(dumpFile, apiConfigDump, 0644)
		if err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %s", dumpFile, err)
		}
		log.Printf("API credentials dumped to '%s'", dumpFile)
	} else {
		fmt.Printf("%s\n", string(apiConfigDump))
	}

	return nil
}

func NewMachinesDeleteCmd() *cobra.Command {
	cmdMachinesDelete := &cobra.Command{
		Use:               "delete [machine_name]...",
		Short:             "delete machines",
		Example:           `cscli machines delete "machine1" "machine2"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			var err error
			dbClient, err = getDBClient()
			if err != nil {
				cobra.CompError("unable to create new database client: " + err.Error())
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			machines, err := dbClient.ListMachines()
			if err != nil {
				cobra.CompError("unable to list machines " + err.Error())
			}
			ret := make([]string, 0)
			for _, machine := range machines {
				if strings.Contains(machine.MachineId, toComplete) && !slices.Contains(args, machine.MachineId) {
					ret = append(ret, machine.MachineId)
				}
			}
			return ret, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: runMachinesDelete,
	}

	return cmdMachinesDelete
}

func runMachinesDelete(cmd *cobra.Command, args []string) error {
	for _, machineID := range args {
		err := dbClient.DeleteWatcher(machineID)
		if err != nil {
			log.Errorf("unable to delete machine '%s': %s", machineID, err)
			return nil
		}
		log.Infof("machine '%s' deleted successfully", machineID)
	}

	return nil
}

func NewMachinesValidateCmd() *cobra.Command {
	cmdMachinesValidate := &cobra.Command{
		Use:               "validate",
		Short:             "validate a machine to access the local API",
		Long:              `validate a machine to access the local API.`,
		Example:           `cscli machines validate "machine_name"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			machineID := args[0]
			if err := dbClient.ValidateMachine(machineID); err != nil {
				return fmt.Errorf("unable to validate machine '%s': %s", machineID, err)
			}
			log.Infof("machine '%s' validated successfully", machineID)

			return nil
		},
	}

	return cmdMachinesValidate
}

func NewMachinesCmd() *cobra.Command {
	var cmdMachines = &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines [requires local API]",
		Long: `To list/add/delete/validate machines.
Note: This command requires database direct access, so is intended to be run on the local API machine.
`,
		Example:           `cscli machines [action]`,
		DisableAutoGenTag: true,
		Aliases:           []string{"machine"},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				if err != nil {
					log.Errorf("local api : %s", err)
				}
				return fmt.Errorf("local API is disabled, please run this command on the local API machine")
			}

			return nil
		},
	}

	cmdMachines.AddCommand(NewMachinesListCmd())
	cmdMachines.AddCommand(NewMachinesAddCmd())
	cmdMachines.AddCommand(NewMachinesDeleteCmd())
	cmdMachines.AddCommand(NewMachinesValidateCmd())

	return cmdMachines
}
