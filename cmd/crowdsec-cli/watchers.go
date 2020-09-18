package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/enescakir/emoji"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var machineID string
var machinePassword string
var machineIP string
var interactive bool

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
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
	}

	var cmdWatchersList = &cobra.Command{
		Use:     "list",
		Short:   "List watchers",
		Long:    `List `,
		Example: `cscli watchers list`,
		Args:    cobra.MaximumNArgs(1),
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
				table.SetHeader([]string{"Name", "IP Address", "Status"})
				for _, w := range watchers {
					var validated string
					if w.IsValidated {
						validated = fmt.Sprintf("%s", emoji.CheckMark)
					} else {
						validated = fmt.Sprintf("%s", emoji.Prohibited)
					}
					table.Append([]string{w.MachineId, w.IpAddress, validated})
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
					fmt.Printf("%s %s %s\n", w.MachineId, w.IpAddress, validated)
				}
			} else {
				log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
			}
		},
	}
	cmdWatchers.AddCommand(cmdWatchersList)

	var cmdWatchersAdd = &cobra.Command{
		Use:     "add",
		Short:   "add watchers",
		Long:    `add `,
		Example: `cscli watchers add --machine test --password testpassword --ip 1.2.3.4`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			if machineID == "" {
				log.Errorf("please provide a machine id with --machine|-m ")
				return
			}
			if machinePassword == "" && !interactive {
				log.Errorf("please provide a password with --password|-p or choose interactive mode to enter the password")
				return
			} else if machinePassword == "" && interactive {
				qs := &survey.Password{
					Message: "Please provide a password for the machine",
				}
				survey.AskOne(qs, &machinePassword)
			}
			password := strfmt.Password(machinePassword)
			_, err := dbClient.CreateMachine(&machineID, &password, machineIP)
			if err != nil {
				log.Errorf("unable to create machine: %s", err)
				return
			}
			log.Infof("Machine '%s' created successfully", machineID)
		},
	}
	cmdWatchersAdd.Flags().StringVarP(&machineID, "machine", "m", "", "machine ID to login to the API")
	cmdWatchersAdd.Flags().StringVarP(&machinePassword, "password", "p", "", "machine password to login to the API")
	cmdWatchersAdd.Flags().StringVar(&machineIP, "ip", "", "machine ip address")
	cmdWatchersAdd.Flags().BoolVarP(&interactive, "interactive", "i", false, "machine ip address")
	cmdWatchers.AddCommand(cmdWatchersAdd)

	var cmdWatchersDelete = &cobra.Command{
		Use:     "delete",
		Short:   "delete watchers",
		Long:    `delete `,
		Example: `cscli watchers delete --machine test`,
		Args:    cobra.MaximumNArgs(1),
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

	return cmdWatchers
}
