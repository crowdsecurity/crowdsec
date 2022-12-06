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
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/machineid"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var machineID string
var machinePassword string
var interactive bool
var apiURL string
var outputFile string
var forceAdd bool
var autoAdd bool

var (
	passwordLength = 64
	upper          = "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower          = "abcdefghijklmnopqrstuvwxyz"
	digits         = "0123456789"
)

func generatePassword(length int) string {
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
	return "", errors.Wrap(err, "generating machine id")
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

func displayLastHeartBeat(m *ent.Machine, fancy bool) string {
	var hbDisplay string

	if m.LastHeartbeat != nil {
		lastHeartBeat := time.Now().UTC().Sub(*m.LastHeartbeat)
		hbDisplay = lastHeartBeat.Truncate(time.Second).String()
		if fancy && lastHeartBeat > 2*time.Minute {
			hbDisplay = fmt.Sprintf("%s %s", emoji.Warning.String(), lastHeartBeat.Truncate(time.Second).String())
		}
	} else {
		hbDisplay = "-"
		if fancy {
			hbDisplay = emoji.Warning.String() + " -"
		}
	}
	return hbDisplay
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
			log.Fatalf("failed to unmarshal")
		}
		return nil
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		err := csvwriter.Write([]string{"machine_id", "ip_address", "updated_at", "validated", "version", "auth_type", "last_heartbeat"})
		if err != nil {
			log.Fatalf("failed to write header: %s", err)
		}
		for _, m := range machines {
			var validated string
			if m.IsValidated {
				validated = "true"
			} else {
				validated = "false"
			}
			err := csvwriter.Write([]string{m.MachineId, m.IpAddress, m.UpdatedAt.Format(time.RFC3339), validated, m.Version, m.AuthType, displayLastHeartBeat(m, false)})
			if err != nil {
				log.Fatalf("failed to write raw output : %s", err)
			}
		}
		csvwriter.Flush()
	} else {
		log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
	}
	return nil
}

func NewMachinesCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdMachines = &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines [requires local API]",
		Long: `To list/add/delete/validate machines.
Note: This command requires database direct access, so is intended to be run on the local API machine.
`,
		Example:           `cscli machines [action]`,
		DisableAutoGenTag: true,
		Aliases:           []string{"machine"},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				if err != nil {
					log.Errorf("local api : %s", err)
				}
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Errorf("This command requires direct database access (must be run on the local API machine)")
				log.Fatal(err)
			}
		},
	}

	var cmdMachinesList = &cobra.Command{
		Use:               "list",
		Short:             "List machines",
		Long:              `List `,
		Example:           `cscli machines list`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			err := getAgents(color.Output, dbClient)
			if err != nil {
				log.Fatalf("unable to list machines: %s", err)
			}
		},
	}
	cmdMachines.AddCommand(cmdMachinesList)

	var cmdMachinesAdd = &cobra.Command{
		Use:               "add",
		Short:             "add machine to the database.",
		DisableAutoGenTag: true,
		Long:              `Register a new machine in the database. cscli should be on the same machine as LAPI.`,
		Example: `
cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword
`,
		PreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var dumpFile string
			var err error

			// create machineID if not specified by user
			if len(args) == 0 {
				if !autoAdd {
					printHelp(cmd)
					return
				}
				machineID, err = generateID("")
				if err != nil {
					log.Fatalf("unable to generate machine id : %s", err)
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
					return
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
				log.Fatalf("unable to create machine: %s", err)
			}
			log.Infof("Machine '%s' successfully added to the local API", machineID)

			if apiURL == "" {
				if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
					apiURL = csConfig.API.Client.Credentials.URL
				} else if csConfig.API.Server != nil && csConfig.API.Server.ListenURI != "" {
					apiURL = "http://" + csConfig.API.Server.ListenURI
				} else {
					log.Fatalf("unable to dump an api URL. Please provide it in your configuration or with the -u parameter")
				}
			}
			apiCfg := csconfig.ApiCredentialsCfg{
				Login:    machineID,
				Password: password.String(),
				URL:      apiURL,
			}
			apiConfigDump, err := yaml.Marshal(apiCfg)
			if err != nil {
				log.Fatalf("unable to marshal api credentials: %s", err)
			}
			if dumpFile != "" && dumpFile != "-" {
				err = os.WriteFile(dumpFile, apiConfigDump, 0644)
				if err != nil {
					log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
				}
				log.Printf("API credentials dumped to '%s'", dumpFile)
			} else {
				fmt.Printf("%s\n", string(apiConfigDump))
			}
		},
	}
	cmdMachinesAdd.Flags().StringVarP(&machinePassword, "password", "p", "", "machine password to login to the API")
	cmdMachinesAdd.Flags().StringVarP(&outputFile, "file", "f", "",
		"output file destination (defaults to "+csconfig.DefaultConfigPath("local_api_credentials.yaml"))
	cmdMachinesAdd.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the local API")
	cmdMachinesAdd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interfactive mode to enter the password")
	cmdMachinesAdd.Flags().BoolVarP(&autoAdd, "auto", "a", false, "automatically generate password (and username if not provided)")
	cmdMachinesAdd.Flags().BoolVar(&forceAdd, "force", false, "will force add the machine if it already exist")
	cmdMachines.AddCommand(cmdMachinesAdd)

	var cmdMachinesDelete = &cobra.Command{
		Use:               "delete --machine MyTestMachine",
		Short:             "delete machines",
		Example:           `cscli machines delete "machine_name"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
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
				if strings.Contains(machine.MachineId, toComplete) && !inSlice(machine.MachineId, args) {
					ret = append(ret, machine.MachineId)
				}
			}
			return ret, cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			machineID = args[0]
			for _, machineID := range args {
				err := dbClient.DeleteWatcher(machineID)
				if err != nil {
					log.Errorf("unable to delete machine '%s': %s", machineID, err)
					return
				}
				log.Infof("machine '%s' deleted successfully", machineID)
			}
		},
	}
	cmdMachinesDelete.Flags().StringVarP(&machineID, "machine", "m", "", "machine to delete")
	cmdMachines.AddCommand(cmdMachinesDelete)

	var cmdMachinesValidate = &cobra.Command{
		Use:               "validate",
		Short:             "validate a machine to access the local API",
		Long:              `validate a machine to access the local API.`,
		Example:           `cscli machines validate "machine_name"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			machineID = args[0]
			if err := dbClient.ValidateMachine(machineID); err != nil {
				log.Fatalf("unable to validate machine '%s': %s", machineID, err)
			}
			log.Infof("machine '%s' validated successfully", machineID)
		},
	}
	cmdMachines.AddCommand(cmdMachinesValidate)

	return cmdMachines
}
