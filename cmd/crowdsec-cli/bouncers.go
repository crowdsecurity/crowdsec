package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
)

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
			return fmt.Errorf("failed to unmarshal: %w", err)
		}
		return nil
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		err := csvwriter.Write([]string{"name", "ip", "revoked", "last_pull", "type", "version", "auth_type"})
		if err != nil {
			return fmt.Errorf("failed to write raw header: %w", err)
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
				return fmt.Errorf("failed to write raw: %w", err)
			}
		}
		csvwriter.Flush()
	}
	return nil
}

func NewBouncersListCmd() *cobra.Command {
	cmdBouncersList := &cobra.Command{
		Use:               "list",
		Short:             "list all bouncers within the database",
		Example:           `cscli bouncers list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			err := getBouncers(color.Output, dbClient)
			if err != nil {
				return fmt.Errorf("unable to list bouncers: %s", err)
			}
			return nil
		},
	}

	return cmdBouncersList
}

func runBouncersAdd(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	keyLength, err := flags.GetInt("length")
	if err != nil {
		return err
	}

	key, err := flags.GetString("key")
	if err != nil {
		return err
	}

	keyName := args[0]
	var apiKey string

	if keyName == "" {
		return fmt.Errorf("please provide a name for the api key")
	}
	apiKey = key
	if key == "" {
		apiKey, err = middlewares.GenerateAPIKey(keyLength)
	}
	if err != nil {
		return fmt.Errorf("unable to generate api key: %s", err)
	}
	_, err = dbClient.CreateBouncer(keyName, "", middlewares.HashSHA512(apiKey), types.ApiKeyAuthType)
	if err != nil {
		return fmt.Errorf("unable to create bouncer: %s", err)
	}

	if csConfig.Cscli.Output == "human" {
		fmt.Printf("API key for '%s':\n\n", keyName)
		fmt.Printf("   %s\n\n", apiKey)
		fmt.Print("Please keep this key since you will not be able to retrieve it!\n")
	} else if csConfig.Cscli.Output == "raw" {
		fmt.Printf("%s", apiKey)
	} else if csConfig.Cscli.Output == "json" {
		j, err := json.Marshal(apiKey)
		if err != nil {
			return fmt.Errorf("unable to marshal api key")
		}
		fmt.Printf("%s", string(j))
	}

	return nil
}

func NewBouncersAddCmd() *cobra.Command {
	cmdBouncersAdd := &cobra.Command{
		Use:   "add MyBouncerName [--length 16]",
		Short: "add a single bouncer to the database",
		Example: `cscli bouncers add MyBouncerName
cscli bouncers add MyBouncerName -l 24
cscli bouncers add MyBouncerName -k <random-key>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE:              runBouncersAdd,
	}

	flags := cmdBouncersAdd.Flags()

	flags.IntP("length", "l", 16, "length of the api key")
	flags.StringP("key", "k", "", "api key for the bouncer")

	return cmdBouncersAdd
}

func runBouncersDelete(cmd *cobra.Command, args []string) error {
	for _, bouncerID := range args {
		err := dbClient.DeleteBouncer(bouncerID)
		if err != nil {
			return fmt.Errorf("unable to delete bouncer '%s': %s", bouncerID, err)
		}
		log.Infof("bouncer '%s' deleted successfully", bouncerID)
	}

	return nil
}

func NewBouncersDeleteCmd() *cobra.Command {
	cmdBouncersDelete := &cobra.Command{
		Use:               "delete MyBouncerName",
		Short:             "delete bouncer(s) from the database",
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			var err error
			dbClient, err = getDBClient()
			if err != nil {
				cobra.CompError("unable to create new database client: " + err.Error())
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			bouncers, err := dbClient.ListBouncers()
			if err != nil {
				cobra.CompError("unable to list bouncers " + err.Error())
			}
			ret := make([]string, 0)
			for _, bouncer := range bouncers {
				if strings.Contains(bouncer.Name, toComplete) && !slices.Contains(args, bouncer.Name) {
					ret = append(ret, bouncer.Name)
				}
			}
			return ret, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: runBouncersDelete,
	}

	return cmdBouncersDelete
}

func NewBouncersPruneCmd() *cobra.Command {
	var parsedDuration time.Duration
	cmdBouncersPrune := &cobra.Command{
		Use:               "prune",
		Short:             "prune multiple bouncers from the database",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Example: `cscli bouncers prune -d 60m
cscli bouncers prune -d 60m --force`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			dur, _ := cmd.Flags().GetString("duration")
			var err error
			parsedDuration, err = time.ParseDuration(fmt.Sprintf("-%s", dur))
			if err != nil {
				return fmt.Errorf("unable to parse duration '%s': %s", dur, err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			if parsedDuration >= 0-2*time.Minute {
				var answer bool
				prompt := &survey.Confirm{
					Message: "The duration you provided is less than or equal 2 minutes this may remove active bouncers continue ?",
					Default: false,
				}
				if err := survey.AskOne(prompt, &answer); err != nil {
					return fmt.Errorf("unable to ask about prune check: %s", err)
				}
				if !answer {
					fmt.Println("user aborted prune no changes were made")
					return nil
				}
			}
			bouncers, err := dbClient.QueryBouncersLastPulltimeLT(time.Now().UTC().Add(parsedDuration))
			if err != nil {
				return fmt.Errorf("unable to query bouncers: %s", err)
			}
			if len(bouncers) == 0 {
				fmt.Println("no bouncers to prune")
				return nil
			}
			getBouncersTable(color.Output, bouncers)
			if !force {
				var answer bool
				prompt := &survey.Confirm{
					Message: "You are about to PERMANENTLY remove the above bouncers from the database these will NOT be recoverable, continue ?",
					Default: false,
				}
				if err := survey.AskOne(prompt, &answer); err != nil {
					return fmt.Errorf("unable to ask about prune check: %s", err)
				}
				if !answer {
					fmt.Println("user aborted prune no changes were made")
					return nil
				}
			}
			nbDeleted, err := dbClient.BulkDeleteBouncers(bouncers)
			if err != nil {
				return fmt.Errorf("unable to prune bouncers: %s", err)
			}
			fmt.Printf("successfully delete %d bouncers\n", nbDeleted)
			return nil
		},
	}
	cmdBouncersPrune.Flags().StringP("duration", "d", "60m", "duration of time since last pull")
	cmdBouncersPrune.Flags().Bool("force", false, "force prune without asking for confirmation")
	return cmdBouncersPrune
}

func NewBouncersCmd() *cobra.Command {
	var cmdBouncers = &cobra.Command{
		Use:   "bouncers [action]",
		Short: "Manage bouncers [requires local API]",
		Long: `To list/add/delete/prune bouncers.
Note: This command requires database direct access, so is intended to be run on Local API/master.
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"bouncer"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if err = require.LAPI(csConfig); err != nil {
				return err
			}

			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %s", err)
			}
			return nil
		},
	}

	cmdBouncers.AddCommand(NewBouncersListCmd())
	cmdBouncers.AddCommand(NewBouncersAddCmd())
	cmdBouncers.AddCommand(NewBouncersDeleteCmd())
	cmdBouncers.AddCommand(NewBouncersPruneCmd())

	return cmdBouncers
}
