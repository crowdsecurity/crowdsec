package main

import (
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var keyName string
var keyIP string
var keyLength int

func NewKeysCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdKeys = &cobra.Command{
		Use:   "keys [action]",
		Short: "Manage local API keys",
		Long: `
API keys Management.

To list/add/delete api keys
`,
		Example: `cscli keys [action]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
	}

	var cmdKeysList = &cobra.Command{
		Use:     "list",
		Short:   "List api keys",
		Long:    `List `,
		Example: `cscli keys list`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			blockers, err := dbClient.ListBlockers()
			if err != nil {
				log.Errorf("unable to list blockers: %s", err)
			}
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
		},
	}
	cmdKeys.AddCommand(cmdKeysList)

	var cmdKeysAdd = &cobra.Command{
		Use:     "add",
		Short:   "add api keys",
		Long:    `add `,
		Example: `cscli keys add --name test [--ip 1.2.3.4]`,
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
	cmdKeysAdd.Flags().StringVarP(&keyName, "name", "n", "", "name to assigned for the api key")
	cmdKeysAdd.Flags().StringVarP(&keyIP, "ip", "i", "", "ip address of the blocker")
	cmdKeysAdd.Flags().IntVarP(&keyLength, "length", "l", 16, "length of the api key")
	cmdKeys.AddCommand(cmdKeysAdd)

	var cmdKeysDelete = &cobra.Command{
		Use:     "delete",
		Short:   "delete api keys",
		Long:    `delete `,
		Example: `cscli keys delete --name test [--ip 1.2.3.4]`,
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
	cmdKeysDelete.Flags().StringVarP(&keyName, "name", "n", "", "name to assigned for the api key")
	cmdKeys.AddCommand(cmdKeysDelete)

	return cmdKeys
}
