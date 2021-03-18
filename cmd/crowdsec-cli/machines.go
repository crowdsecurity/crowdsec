package main

import (
	saferand "crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/denisbrodbeck/machineid"
	"github.com/enescakir/emoji"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
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

const (
	uuid = "/proc/sys/kernel/random/uuid"
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

func generateID() (string, error) {
	id, err := machineid.ID()
	if err != nil {
		log.Debugf("failed to get machine-id with usual files : %s", err)
	}
	if id == "" || err != nil {
		bID, err := ioutil.ReadFile(uuid)
		if err != nil {
			return "", errors.Wrap(err, "generating machine id")
		}
		id = string(bID)
	}
	id = strings.ReplaceAll(id, "-", "")[:32]
	id = fmt.Sprintf("%s%s", id, generatePassword(16))
	return id, nil
}

func NewMachinesCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdMachines = &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines (need root permissions)",
		Long: `
Machines Management.

To list/add/delete/validate machines
`,
		Example: `cscli machines [action]`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			isUserRoot, err := isRoot()
			if err != nil {
				log.Fatalf(err.Error())
			}
			if !isUserRoot {
				log.Fatalf("you must run this command as root or with sudo")
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Fatalf(err.Error())
			}
			return nil
		},
	}

	var cmdMachinesList = &cobra.Command{
		Use:     "list",
		Short:   "List machines",
		Long:    `List `,
		Example: `cscli machines list`,
		Args:    cobra.MaximumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error

			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			machines, err := dbClient.ListMachines()
			if err != nil {
				log.Errorf("unable to list blockers: %s", err)
			}
			if csConfig.Cscli.Output == "human" {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Name", "IP Address", "Last Update", "Status", "Version"})
				for _, w := range machines {
					var validated string
					if w.IsValidated {
						validated = fmt.Sprintf("%s", emoji.CheckMark)
					} else {
						validated = fmt.Sprintf("%s", emoji.Prohibited)
					}
					table.Append([]string{w.MachineId, w.IpAddress, w.UpdatedAt.Format(time.RFC3339), validated, w.Version})
				}
				table.Render()
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(machines, "", " ")
				if err != nil {
					log.Fatalf("failed to unmarshal")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				for _, w := range machines {
					var validated string
					if w.IsValidated {
						validated = "true"
					} else {
						validated = "false"
					}
					fmt.Printf("%s,%s,%s,%s,%s\n", w.MachineId, w.IpAddress, w.UpdatedAt.Format(time.RFC3339), validated, w.Version)
				}
			} else {
				log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
			}
		},
	}
	cmdMachines.AddCommand(cmdMachinesList)

	var cmdMachinesAdd = &cobra.Command{
		Use:   "add",
		Short: "add machine to the database.",
		Long:  `Register a new machine in the database. cscli should be on the same machine as LAPI.`,
		Example: `
cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword
`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var dumpFile string
			var err error

			// create machineID if doesn't specified by user
			if len(args) == 0 {
				if !autoAdd {
					err = cmd.Help()
					if err != nil {
						log.Fatalf("unable to print help(): %s", err)
					}
					return
				}
				machineID, err = generateID()
				if err != nil {
					log.Fatalf("unable to generate machine id : %s", err)
				}
			} else {
				machineID = args[0]
			}

			/*check if file already exists*/
			if outputFile != "" {
				dumpFile = outputFile
			} else if csConfig.API.Client.CredentialsFilePath != "" {
				dumpFile = csConfig.API.Client.CredentialsFilePath
			}

			// create password if doesn't specified by user
			if machinePassword == "" && !interactive {
				if !autoAdd {
					err = cmd.Help()
					if err != nil {
						log.Fatalf("unable to print help(): %s", err)
					}
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
			_, err = dbClient.CreateMachine(&machineID, &password, "", true, forceAdd)
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
			if dumpFile != "" {
				err = ioutil.WriteFile(dumpFile, apiConfigDump, 0644)
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
	cmdMachinesAdd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination (defaults to /etc/crowdsec/local_api_credentials.yaml)")
	cmdMachinesAdd.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the local API")
	cmdMachinesAdd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interfactive mode to enter the password")
	cmdMachinesAdd.Flags().BoolVarP(&autoAdd, "auto", "a", false, "automatically generate password (and username if not provided)")
	cmdMachinesAdd.Flags().BoolVar(&forceAdd, "force", false, "will force add the machine if it already exist")
	cmdMachines.AddCommand(cmdMachinesAdd)

	var cmdMachinesDelete = &cobra.Command{
		Use:     "delete --machine MyTestMachine",
		Short:   "delete machines",
		Example: `cscli machines delete <machine_name>`,
		Args:    cobra.ExactArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			machineID = args[0]
			err := dbClient.DeleteWatcher(machineID)
			if err != nil {
				log.Errorf("unable to delete machine: %s", err)
				return
			}
			log.Infof("machine '%s' deleted successfully", machineID)
		},
	}
	cmdMachinesDelete.Flags().StringVarP(&machineID, "machine", "m", "", "machine to delete")
	cmdMachines.AddCommand(cmdMachinesDelete)

	var cmdMachinesValidate = &cobra.Command{
		Use:     "validate",
		Short:   "validate a machine to access the local API",
		Long:    `validate a machine to access the local API.`,
		Example: `cscli machines validate <machine_name>`,
		Args:    cobra.ExactArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
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
			log.Infof("machine '%s' validated successfuly", machineID)
		},
	}
	cmdMachines.AddCommand(cmdMachinesValidate)

	return cmdMachines
}
