package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var keyIP string
var keyLength int
var key string

func getBouncers(out io.Writer, dbClient *database.Client) error {
	bouncers, err := dbClient.ListBouncers()
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %s", err)
	}
	if csConfig.Cscli.Output == "human" {
		getBouncersTable(out, bouncers)
	} else if csConfig.Cscli.Output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(bouncers); err != nil {
			return errors.Wrap(err, "failed to unmarshal")
		}
		return nil
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		err := csvwriter.Write([]string{"name", "ip", "revoked", "last_pull", "type", "version", "auth_type"})
		if err != nil {
			return errors.Wrap(err, "failed to write raw header")
		}
		for _, b := range bouncers {
			var revoked string
			if !b.Revoked {
				revoked = "validated"
			} else {
				revoked = "pending"
			}
			err := csvwriter.Write([]string{b.Name, b.IPAddress, revoked, b.LastPull.Format(time.RFC3339), b.Type, b.Version, b.AuthType})
			if err != nil {
				return errors.Wrap(err, "failed to write raw")
			}
		}
		csvwriter.Flush()
	}
	return nil
}

func NewBouncersCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdBouncers = &cobra.Command{
		Use:   "bouncers [action]",
		Short: "Manage bouncers [requires local API]",
		Long: `To list/add/delete bouncers.
Note: This command requires database direct access, so is intended to be run on Local API/master.
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"bouncer"},
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
			err := getBouncers(color.Output, dbClient)
			if err != nil {
				log.Fatalf("unable to list bouncers: %s", err)
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
			_, err = dbClient.CreateBouncer(keyName, keyIP, middlewares.HashSHA512(apiKey), types.ApiKeyAuthType)
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
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, bouncerID := range args {
				err := dbClient.DeleteBouncer(bouncerID)
				if err != nil {
					log.Fatalf("unable to delete bouncer '%s': %s", bouncerID, err)
				}
				log.Infof("bouncer '%s' deleted successfully", bouncerID)
			}
		},
	}
	cmdBouncers.AddCommand(cmdBouncersDelete)
	return cmdBouncers
}
