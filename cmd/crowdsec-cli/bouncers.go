package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func askYesNo(message string, defaultAnswer bool) (bool, error) {
	var answer bool
	prompt := &survey.Confirm{
		Message: message,
		Default: defaultAnswer,
	}

	if err := survey.AskOne(prompt, &answer); err != nil {
		return defaultAnswer, err
	}

	return answer, nil
}

type cliBouncers struct {
	db *database.Client
}

func NewCLIBouncers() *cliBouncers {
	return &cliBouncers{}
}

func (cli *cliBouncers) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bouncers [action]",
		Short: "Manage bouncers [requires local API]",
		Long: `To list/add/delete/prune bouncers.
Note: This command requires database direct access, so is intended to be run on Local API/master.
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"bouncer"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			var err error
			if err = require.DB(csConfig); err != nil {
				return err
			}

			cli.db, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				return fmt.Errorf("can't connect to the database: %s", err)
			}
			return nil
		},
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newPruneCmd())

	return cmd
}

func (cli *cliBouncers) list() error {
	out := color.Output

	bouncers, err := cli.db.ListBouncers()
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %s", err)
	}

	switch csConfig.Cscli.Output {
	case "human":
		getBouncersTable(out, bouncers)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(bouncers); err != nil {
			return fmt.Errorf("failed to unmarshal: %w", err)
		}
		return nil
	case "raw":
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

func (cli *cliBouncers) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list all bouncers within the database",
		Example:           `cscli bouncers list`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.list()
		},
	}

	return cmd
}

func (cli *cliBouncers) add(bouncerName string, key string) error {
	var err error

	keyLength := 32

	if key == "" {
		key, err = middlewares.GenerateAPIKey(keyLength)
		if err != nil {
			return fmt.Errorf("unable to generate api key: %s", err)
		}
	}
	_, err = cli.db.CreateBouncer(bouncerName, "", middlewares.HashSHA512(key), types.ApiKeyAuthType)
	if err != nil {
		return fmt.Errorf("unable to create bouncer: %s", err)
	}

	switch csConfig.Cscli.Output {
	case "human":
		fmt.Printf("API key for '%s':\n\n", bouncerName)
		fmt.Printf("   %s\n\n", key)
		fmt.Print("Please keep this key since you will not be able to retrieve it!\n")
	case "raw":
		fmt.Print(key)
	case "json":
		j, err := json.Marshal(key)
		if err != nil {
			return fmt.Errorf("unable to marshal api key")
		}
		fmt.Print(string(j))
	}

	return nil
}

func (cli *cliBouncers) newAddCmd() *cobra.Command {
	var key string

	cmd := &cobra.Command{
		Use:   "add MyBouncerName",
		Short: "add a single bouncer to the database",
		Example: `cscli bouncers add MyBouncerName
cscli bouncers add MyBouncerName --key <random-key>`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.add(args[0], key)
		},
	}

	flags := cmd.Flags()
	flags.StringP("length", "l", "", "length of the api key")
	flags.MarkDeprecated("length", "use --key instead")
	flags.StringVarP(&key, "key", "k", "", "api key for the bouncer")

	return cmd
}

func (cli *cliBouncers) deleteValid(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error
	bouncers, err := cli.db.ListBouncers()
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
}

func (cli *cliBouncers) delete(bouncers []string) error {
	for _, bouncerID := range bouncers {
		err := cli.db.DeleteBouncer(bouncerID)
		if err != nil {
			return fmt.Errorf("unable to delete bouncer '%s': %s", bouncerID, err)
		}
		log.Infof("bouncer '%s' deleted successfully", bouncerID)
	}

	return nil
}

func (cli *cliBouncers) newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "delete MyBouncerName",
		Short:             "delete bouncer(s) from the database",
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.deleteValid,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.delete(args)
		},
	}

	return cmd
}

func (cli *cliBouncers) prune(duration time.Duration, force bool) error {
	if duration < 2*time.Minute {
		if yes, err := askYesNo(
				"The duration you provided is less than 2 minutes. " +
				"This may remove active bouncers. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	bouncers, err := cli.db.QueryBouncersLastPulltimeLT(time.Now().UTC().Add(duration))
	if err != nil {
		return fmt.Errorf("unable to query bouncers: %w", err)
	}

	if len(bouncers) == 0 {
		fmt.Println("No bouncers to prune.")
		return nil
	}

	getBouncersTable(color.Output, bouncers)

	if !force {
		if yes, err := askYesNo(
				"You are about to PERMANENTLY remove the above bouncers from the database. " +
				"These will NOT be recoverable. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	deleted, err := cli.db.BulkDeleteBouncers(bouncers)
	if err != nil {
		return fmt.Errorf("unable to prune bouncers: %s", err)
	}

	fmt.Printf("Successfully deleted %d bouncers\n", deleted)

	return nil
}

func (cli *cliBouncers) newPruneCmd() *cobra.Command {
	var (
		duration time.Duration
		force    bool
	)

	defaultDuration := 60 * time.Minute

	cmd := &cobra.Command{
		Use:               "prune",
		Short:             "prune multiple bouncers from the database",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Example: `cscli bouncers prune -d 45m
cscli bouncers prune -d 45m --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.prune(duration, force)
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", defaultDuration, "duration of time since last pull")
	flags.BoolVar(&force, "force", false, "force prune without asking for confirmation")
	return cmd
}
