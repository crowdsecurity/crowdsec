package main

import (
	"encoding/csv"
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

var keyIP string
var keyLength int
var key string

func NewBouncersCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdBouncers = &cobra.Command{
		Use:   "bouncers [action]",
		Short: "Manage bouncers [requires local API]",
		Long: `To list/add/delete bouncers.
Note: This command requires database direct access, so is intended to be run on Local API/master.
`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Fatalf(err.Error())
			}
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
		},
	}

	var cmdBouncersList = &cobra.Command{
		Use:               "list",
		Short:             "List bouncers",
		Long:              `List bouncers`,
		Example:           `cscli bouncers list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, arg []string) {
			blockers, err := dbClient.ListBouncers()
			if err != nil {
				log.Errorf("unable to list blockers: %s", err)
			}
			if csConfig.Cscli.Output == "human" {

				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetHeader([]string{"Name", "IP Address", "Valid", "Last API pull", "Type", "Version"})
				for _, b := range blockers {
					var revoked string
					if !b.Revoked {
						revoked = fmt.Sprintf("%s", emoji.CheckMark)
					} else {
						revoked = fmt.Sprintf("%s", emoji.Prohibited)
					}
					table.Append([]string{b.Name, b.IPAddress, revoked, b.LastPull.Format(time.RFC3339), b.Type, b.Version})
				}
				table.Render()
			} else if csConfig.Cscli.Output == "json" {
				x, err := json.MarshalIndent(blockers, "", " ")
				if err != nil {
					log.Fatalf("failed to unmarshal")
				}
				fmt.Printf("%s", string(x))
			} else if csConfig.Cscli.Output == "raw" {
				csvwriter := csv.NewWriter(os.Stdout)
				err := csvwriter.Write([]string{"name", "ip", "revoked", "last_pull", "type", "version"})
				if err != nil {
					log.Fatalf("failed to write raw header: %s", err)
				}
				for _, b := range blockers {
					var revoked string
					if !b.Revoked {
						revoked = "validated"
					} else {
						revoked = "pending"
					}
					err := csvwriter.Write([]string{b.Name, b.IPAddress, revoked, b.LastPull.Format(time.RFC3339), b.Type, b.Version})
					if err != nil {
						log.Fatalf("failed to write raw: %s", err)
					}
				}
				csvwriter.Flush()
			}
		},
	}
	cmdBouncers.AddCommand(cmdBouncersList)

	var cmdBouncersAdd = &cobra.Command{
		Use:   "add MyBouncerName [--length 16]",
		Short: "add bouncer",
		Long:  `add bouncer`,
		Example: fmt.Sprintf(`cscli bouncers add MyBouncerName
cscli bouncers add MyBouncerName -l 24
cscli bouncers add MyBouncerName -k %s`, generatePassword(32)),
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, arg []string) {
			keyName := arg[0]
			var apiKey string
			var err error
			if keyName == "" {
				log.Fatalf("Please provide a name for the api key")
			}
			apiKey = key
			if key == "" {
				apiKey, err = middlewares.GenerateAPIKey(keyLength)
			}
			if err != nil {
				log.Fatalf("unable to generate api key: %s", err)
			}
			err = dbClient.CreateBouncer(keyName, keyIP, middlewares.HashSHA512(apiKey))
			if err != nil {
				log.Fatalf("unable to create bouncer: %s", err)
			}

			if csConfig.Cscli.Output == "human" {
				fmt.Printf("Api key for '%s':\n\n", keyName)
				fmt.Printf("   %s\n\n", apiKey)
				fmt.Print("Please keep this key since you will not be able to retrieve it!\n")
			} else if csConfig.Cscli.Output == "raw" {
				fmt.Printf("%s", apiKey)
			} else if csConfig.Cscli.Output == "json" {
				j, err := json.Marshal(apiKey)
				if err != nil {
					log.Fatalf("unable to marshal api key")
				}
				fmt.Printf("%s", string(j))
			}
		},
	}
	cmdBouncersAdd.Flags().IntVarP(&keyLength, "length", "l", 16, "length of the api key")
	cmdBouncersAdd.Flags().StringVarP(&key, "key", "k", "", "api key for the bouncer")
	cmdBouncers.AddCommand(cmdBouncersAdd)

	var cmdBouncersDelete = &cobra.Command{
		Use:               "delete MyBouncerName",
		Short:             "delete bouncer",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, bouncerID := range args {
				err := dbClient.DeleteBouncer(bouncerID)
				if err != nil {
					log.Fatalf("unable to delete bouncer: %s", err)
				}
				log.Infof("bouncer '%s' deleted successfully", bouncerID)
			}
		},
	}
	cmdBouncers.AddCommand(cmdBouncersDelete)
	return cmdBouncers
}
