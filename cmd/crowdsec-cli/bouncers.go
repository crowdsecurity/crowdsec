package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var keyName string
var keyIP string
var keyLength int

func NewBouncersCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdBouncers = &cobra.Command{
		Use:   "bouncers [action]",
		Short: "Manage bouncers",
		Long: `
Bouncers Management.

To list/add/delete bouncers
`,
		Example: `cscli bouncers [action]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
	}

	var cmdBouncersList = &cobra.Command{
		Use:     "list",
		Short:   "List bouncers",
		Long:    `List bouncers`,
		Example: `cscli bouncers list`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			blockers, err := dbClient.ListBlockers()
			if err != nil {
				log.Errorf("unable to list blockers: %s", err)
			}
			if csConfig.Cscli.Output == "human" {

				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Name", "IP Address", "Valid", "Last API pull"})
				for _, b := range blockers {
					var revoked string
					if !b.Revoked {
						revoked = fmt.Sprintf("%s", emoji.CheckMark)
					} else {
						revoked = fmt.Sprintf("%s", emoji.Prohibited)
					}
					table.Append([]string{b.Name, b.IPAddress, revoked, fmt.Sprintf("%s", b.LastPull.Format(time.RFC3339))})
				}
				table.Render()
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(blockers, "", " ")
				if err != nil {
					log.Fatalf("failed to unmarshal")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				for _, b := range blockers {
					var revoked string
					if !b.Revoked {
						revoked = "validated"
					} else {
						revoked = "pending"
					}
					fmt.Printf("%s,%s,%s,%s\n", b.Name, b.IPAddress, revoked, fmt.Sprintf("%s", b.LastPull.Format(time.RFC3339)))
				}
			} else {
				log.Errorf("unknown output '%s'", csConfig.Cscli.Output)
			}

		},
	}
	cmdBouncers.AddCommand(cmdBouncersList)

	var cmdBouncersAdd = &cobra.Command{
		Use:     "add",
		Short:   "add bouncer",
		Long:    `add bouncer`,
		Example: `cscli bouncers add --name test [--ip 1.2.3.4]`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			if keyName == "" {
				log.Errorf("Please provide a name for the api key with the --name|-n parameter")
				return
			}
			apiKey, err := middlewares.GenerateAPIKey(keyLength)
			if err != nil {
				log.Errorf("unable to generate api key: %s", err)
				return
			}
			err = dbClient.CreateBlocker(keyName, keyIP, middlewares.HashSHA512(apiKey))
			if err != nil {
				log.Errorf("unable to create blocker: %s", err)
				return
			}
			fmt.Printf("Api key for '%s':\n\n", keyName)
			fmt.Printf("   %s\n\n", apiKey)
			fmt.Print("Please keep this key since will not be able to retrive it!\n")
		},
	}
	cmdBouncersAdd.Flags().StringVarP(&keyName, "name", "n", "", "name to assigned for the api key")
	cmdBouncersAdd.Flags().StringVarP(&keyIP, "ip", "i", "", "ip address of the blocker")
	cmdBouncersAdd.Flags().IntVarP(&keyLength, "length", "l", 16, "length of the api key")
	cmdBouncers.AddCommand(cmdBouncersAdd)

	var cmdBouncersDelete = &cobra.Command{
		Use:     "delete",
		Short:   "delete bouncer",
		Long:    `delete bouncer`,
		Example: `cscli bouncers delete --name test [--ip 1.2.3.4]`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			if keyName == "" {
				log.Errorf("Please provide a name for the api key with the --name|-n parameter")
				return
			}
			err := dbClient.DeleteBlocker(keyName)
			if err != nil {
				log.Errorf("unable to create blocker: %s", err)
				return
			}
		},
	}
	cmdBouncersDelete.Flags().StringVarP(&keyName, "name", "n", "", "name to assigned for the api key")
	cmdBouncers.AddCommand(cmdBouncersDelete)

	return cmdBouncers
}
