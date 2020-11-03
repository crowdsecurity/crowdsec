package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
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
	rand.Seed(time.Now().UnixNano())
	charset := upper + lower + digits

	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = upper[rand.Intn(len(upper))]
	buf[2] = lower[rand.Intn(len(lower))]

	for i := 3; i < length; i++ {
		buf[i] = charset[rand.Intn(len(charset))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})

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
		id = strings.ReplaceAll(id, "-", "")[:32]
	}
	id = fmt.Sprintf("%s%s", id, generatePassword(16))
	return id, nil
}

func NewMachinesCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdMachines = &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines",
		Long: `
Machines Management.

To list/add/delete machines
`,
		Example: `cscli machines [action]`,
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
		Run: func(cmd *cobra.Command, arg []string) {
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
		Example: `cscli machines add -m MyTestMachine -a
cscli machines add --machine TestMachine --password password
`,
		Args: cobra.ExactArgs(0),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, arg []string) {
			var err error

			// create machineID if doesn't specified by user
			if machineID == "" {
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
			log.Infof("Machine '%s' created successfully", machineID)

			var dumpFile string
			if outputFile != "" {
				dumpFile = outputFile
			} else if csConfig.API.Client.CredentialsFilePath != "" {
				dumpFile = csConfig.API.Client.CredentialsFilePath
			} else {
				dumpFile = ""
			}
			if apiURL == "" {
				if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
					apiURL = csConfig.API.Client.Credentials.URL
				} else if csConfig.API.Server != nil && csConfig.API.Server.ListenURI != "" {
					apiURL = csConfig.API.Server.ListenURI
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
	cmdMachinesAdd.Flags().StringVarP(&machineID, "machine", "m", "", "machine ID to login to the API")
	cmdMachinesAdd.Flags().StringVarP(&machinePassword, "password", "p", "", "machine password to login to the API")
	cmdMachinesAdd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmdMachinesAdd.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the API")
	cmdMachinesAdd.Flags().BoolVarP(&interactive, "interactive", "i", false, "machine ip address")
	cmdMachinesAdd.Flags().BoolVarP(&autoAdd, "auto", "a", false, "add the machine automatically (generate the machine ID and the password)")
	cmdMachinesAdd.Flags().BoolVar(&forceAdd, "force", false, "will force if the machine was already added")
	cmdMachines.AddCommand(cmdMachinesAdd)

	var cmdMachinesDelete = &cobra.Command{
		Use:     "delete --machine MyTestMachine",
		Short:   "delete machines",
		Example: `cscli machines delete --machine test`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, arg []string) {
			if machineID == "" {
				log.Errorf("Please provide a name for the watcher you want to delete with --machine|-m")
				return
			}
			err := dbClient.DeleteWatcher(machineID)
			if err != nil {
				log.Errorf("unable to create blocker: %s", err)
				return
			}
		},
	}
	cmdMachinesDelete.Flags().StringVarP(&machineID, "machine", "m", "", "machine to delete")
	cmdMachines.AddCommand(cmdMachinesDelete)

	var cmdMachinesRegister = &cobra.Command{
		Use:   "register -u http://127.0.0.1:8080/",
		Short: "register a machine to a remote API",
		Long: `register a machine to a remote API.
/!\ The machine will not be validated. You have to connect on the remote API server and run 'cscli machine validate -m <machine_id>'`,
		Example: `cscli machine register`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			var err error
			id, err := generateID()
			if err != nil {
				log.Fatalf("unable to generate machine id: %s", err)
			}
			password := strfmt.Password(generatePassword(passwordLength))
			if apiURL == "" {
				if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
					apiURL = csConfig.API.Client.Credentials.URL
				} else {
					log.Fatalf("unable to dump an api URL. Please provide it in your configuration or with the -u parameter")
				}
			}
			apiurl, err := url.Parse(apiURL)
			if err != nil {
				log.Fatalf("parsing api url: %s", err)
			}
			_, err = apiclient.RegisterClient(&apiclient.Config{
				MachineID:     id,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiurl,
				VersionPrefix: "v1",
			}, nil)

			if err != nil {
				log.Fatalf("api client register: %s", err)
			}

			var dumpFile string
			if outputFile != "" {
				dumpFile = outputFile
			} else if csConfig.API.Client.CredentialsFilePath != "" {
				dumpFile = csConfig.API.Client.CredentialsFilePath
			} else {
				dumpFile = ""
			}
			apiCfg := csconfig.ApiCredentialsCfg{
				Login:    id,
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
	cmdMachinesRegister.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the API")
	cmdMachinesRegister.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmdMachines.AddCommand(cmdMachinesRegister)

	var cmdMachinesValidate = &cobra.Command{
		Use:     "validate",
		Short:   "validate a machine to access the local API",
		Long:    `validate a machine to access the local API.`,
		Example: `cscli machines validate --machine test`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, arg []string) {
			if machineID == "" {
				log.Fatalf("please provide a machine to delete with --machine|-m")
			}
			if err := dbClient.ValidateMachine(machineID); err != nil {
				log.Fatalf("unable to validate machine '%s': %s", machineID, err)
			}
			log.Infof("machine '%s' validated successfuly", machineID)
		},
	}
	cmdMachinesValidate.Flags().StringVarP(&machineID, "machine", "m", "", "machine to validate")
	cmdMachines.AddCommand(cmdMachinesValidate)

	return cmdMachines
}
