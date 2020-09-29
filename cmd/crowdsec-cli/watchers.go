package main

import (
	"context"
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
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/denisbrodbeck/machineid"
	"github.com/enescakir/emoji"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var machineID string
var machinePassword string
var machineIP string
var interactive bool
var apiURL string
var dumpCreds bool
var outputFile string

var (
	passwordLength = 64
	upper          = "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower          = "abcdefghijklmnopqrstuvwxyz"
	digits         = "0123456789"
)

const (
	uuid = "/proc/sys/kernel/random/uuid"
)

func generatePassword() string {
	rand.Seed(time.Now().UnixNano())
	charset := upper + lower + digits

	buf := make([]byte, passwordLength)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = upper[rand.Intn(len(upper))]
	buf[2] = lower[rand.Intn(len(lower))]

	for i := 3; i < passwordLength; i++ {
		buf[i] = charset[rand.Intn(len(charset))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})

	return string(buf)
}

func NewWatchersCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdWatchers = &cobra.Command{
		Use:   "watchers [action]",
		Short: "Manage local API watchers",
		Long: `
Watchers Management.

To list/add/delete watchers
`,
		Example: `cscli watchers [action]`,
	}

	var cmdWatchersList = &cobra.Command{
		Use:     "list",
		Short:   "List watchers",
		Long:    `List `,
		Example: `cscli watchers list`,
		Args:    cobra.MaximumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, arg []string) {
			watchers, err := dbClient.ListWatchers()
			if err != nil {
				log.Errorf("unable to list blockers: %s", err)
			}
			if csConfig.Cscli.Output == "human" {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Name", "IP Address", "Last Update", "Status"})
				for _, w := range watchers {
					var validated string
					if w.IsValidated {
						validated = fmt.Sprintf("%s", emoji.CheckMark)
					} else {
						validated = fmt.Sprintf("%s", emoji.Prohibited)
					}
					table.Append([]string{w.MachineId, w.IpAddress, w.UpdatedAt.Format(time.RFC3339), validated})
				}
				table.Render()
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(watchers, "", " ")
				if err != nil {
					log.Fatalf("failed to unmarshal")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				for _, w := range watchers {
					var validated string
					if w.IsValidated {
						validated = "true"
					} else {
						validated = "false"
					}
					fmt.Printf("%s,%s,%s,%s\n", w.MachineId, w.IpAddress, w.UpdatedAt.Format(time.RFC3339), validated)
				}
			} else {
				log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
			}
		},
	}
	cmdWatchers.AddCommand(cmdWatchersList)

	var cmdWatchersAdd = &cobra.Command{
		Use:   "add",
		Short: "add watchers directly to the database.",
		Long: `add watchers directly to the database.
The watcher will be validated automatically.
/!\ This will add the watcher only in the local database. This can't be run from a remote server.`,
		Example: `cscli watchers add --machine test --password testpassword --ip 1.2.3.4`,
		Args:    cobra.MaximumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, arg []string) {
			if machineID == "" {
				log.Fatalf("please provide a machine id with --machine|-m ")
			}
			if machinePassword == "" && !interactive {
				log.Fatalf("please provide a password with --password|-p or choose interactive mode to enter the password")
			} else if machinePassword == "" && interactive {
				qs := &survey.Password{
					Message: "Please provide a password for the machine",
				}
				survey.AskOne(qs, &machinePassword)
			}
			password := strfmt.Password(machinePassword)
			_, err := dbClient.CreateMachine(&machineID, &password, machineIP, true)
			if err != nil {
				log.Fatalf("unable to create machine: %s", err)
			}
			log.Infof("Machine '%s' created successfully", machineID)

			var dumpFile string
			if csConfig.API.Client.CredentialsFilePath == "" {
				dumpFile = "./api_credentials.yaml"
			} else {
				dumpFile = csConfig.API.Client.CredentialsFilePath
			}
			if apiURL == "" {
				if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil && csConfig.API.Client.Credentials.URL != "" {
					apiURL = csConfig.API.Client.Credentials.URL
				} else if csConfig.API.Server != nil {
					apiURL = csConfig.API.Server.ListenURI
				}
				if apiURL == "" {
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
			err = ioutil.WriteFile(dumpFile, apiConfigDump, 0644)
			if err != nil {
				log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
			}
			log.Printf("API credentials dumped to '%s'", dumpFile)

		},
	}
	cmdWatchersAdd.Flags().StringVarP(&machineID, "machine", "m", "", "machine ID to login to the API")
	cmdWatchersAdd.Flags().StringVarP(&machinePassword, "password", "p", "", "machine password to login to the API")
	cmdWatchersAdd.Flags().StringVar(&machineIP, "ip", "", "machine ip address")
	cmdWatchersAdd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmdWatchersAdd.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the API")
	cmdWatchersAdd.Flags().BoolVarP(&interactive, "interactive", "i", false, "machine ip address")
	cmdWatchers.AddCommand(cmdWatchersAdd)

	var cmdWatchersDelete = &cobra.Command{
		Use:     "delete",
		Short:   "delete watchers",
		Long:    `delete `,
		Example: `cscli watchers delete --machine test`,
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
	cmdWatchersDelete.Flags().StringVarP(&machineID, "machine", "m", "", "machine to delete")
	cmdWatchers.AddCommand(cmdWatchersDelete)

	var cmdWatchersRegister = &cobra.Command{
		Use:   "register",
		Short: "register a watcher to a remote API",
		Long: `register a watcher to a remote API.
/!\ The watcher will not be validated. You have to connect on the remote API server and run 'cscli validate watcher <machine_id>'`,
		Example: `cscli watchers add --machine test --password testpassword --ip 1.2.3.4`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			id, err := machineid.ID()
			if err != nil {
				log.Debugf("failed to get machine-id with usual files : %s", err)
			}
			if id == "" || err != nil {
				bID, err := ioutil.ReadFile(uuid)
				if err != nil {
					log.Fatalf("can'get a valid machine_id")
				}
				id = string(bID)
				id = strings.ReplaceAll(id, "-", "")[:32]
			}
			password := strfmt.Password(generatePassword())
			if apiURL != "" {
				if csConfig.API.Client.Credentials != nil {
					apiURL = csConfig.API.Client.Credentials.URL
				} else if csConfig.API.Server != nil && csConfig.API.Server.ListenURI != "" {
					apiURL = csConfig.API.Server.ListenURI
				}
			}
			apiclient.BaseURL, err = url.Parse(apiURL)
			if err != nil {
				log.Fatalf("unable to parse API Client URL '%s' : %s", apiURL, err)
			}
			Client = apiclient.NewClient(nil)
			_, err = Client.Auth.RegisterWatcher(context.Background(), models.WatcherRegistrationRequest{MachineID: &id, Password: &password})
			if err != nil {
				log.Fatalf("unable to register to API (%s) : %s", Client.BaseURL, err)
			}

			if !dumpCreds {
				fmt.Printf("url: %s\n", csConfig.API.Client.Credentials.URL)
				fmt.Printf("machine_id: %s\n", id)
				fmt.Printf("password: %s\n", password.String())
				return
			}

			var dumpFile string
			if csConfig.API.Client.CredentialsFilePath == "" {
				dumpFile = "./api_credentials.yaml"
			} else {
				dumpFile = csConfig.API.Client.CredentialsFilePath
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
			err = ioutil.WriteFile(dumpFile, apiConfigDump, 0644)
			if err != nil {
				log.Fatalf("write api credentials in '%s' failed: %s", dumpFile, err)
			}
			log.Printf("API credentials dumped to '%s'", dumpFile)
		},
	}
	cmdWatchersDelete.Flags().StringVarP(&apiURL, "url", "u", "", "URL of the API")
	cmdWatchersDelete.Flags().BoolVarP(&dumpCreds, "dump", "d", false, "dump credentials to the file specified in configuration")
	cmdWatchers.AddCommand(cmdWatchersRegister)

	var cmdWatchersValidate = &cobra.Command{
		Use:     "validate",
		Short:   "validate a watcher to access the local API",
		Long:    `validate a watcher to access the local API.`,
		Example: `cscli watchers add --machine test --password testpassword --ip 1.2.3.4`,
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
	cmdWatchersValidate.Flags().StringVarP(&machineID, "machine", "m", "", "machine to validate")
	cmdWatchers.AddCommand(cmdWatchersValidate)

	return cmdWatchers
}
