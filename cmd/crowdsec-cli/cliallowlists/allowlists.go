package cliallowlists

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type configGetter = func() *csconfig.Config

type cliAllowLists struct {
	db     *database.Client
	client *apiclient.ApiClient
	cfg    configGetter
}

func New(cfg configGetter) *cliAllowLists {
	return &cliAllowLists{
		cfg: cfg,
	}
}

// validAllowlists returns a list of valid allowlists name for command completion
// Used for completion in cscli by commands that allow editing (add), so it excludes allowlists managed by console
func (cli *cliAllowLists) validAllowlists(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error

	cfg := cli.cfg()
	ctx := cmd.Context()

	// need to load config and db because PersistentPreRunE is not called for completions

	if err = require.LAPI(cfg); err != nil {
		cobra.CompError("unable to load LAPI " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cli.db, err = require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		cobra.CompError("unable to load dbclient " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	allowlists, err := cli.db.ListAllowLists(ctx, false)
	if err != nil {
		cobra.CompError("unable to list allowlists " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ret := []string{}

	for _, allowlist := range allowlists {
		if strings.Contains(allowlist.Name, toComplete) && !slices.Contains(args, allowlist.Name) && !allowlist.FromConsole {
			ret = append(ret, allowlist.Name)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

// Used for completion in cscli
// This version returns a list of all allowlists, including those managed by console (for completion in read-only commands, such as inspect)
func (cli *cliAllowLists) validAllowlistsWithConsole(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error

	cfg := cli.cfg()
	ctx := cmd.Context()

	// need to load config and db because PersistentPreRunE is not called for completions

	if err = require.LAPI(cfg); err != nil {
		cobra.CompError("unable to load LAPI " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cli.db, err = require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		cobra.CompError("unable to load dbclient " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	allowlists, err := cli.db.ListAllowLists(ctx, false)
	if err != nil {
		cobra.CompError("unable to list allowlists " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ret := []string{}

	for _, allowlist := range allowlists {
		if strings.Contains(allowlist.Name, toComplete) && !slices.Contains(args, allowlist.Name) {
			ret = append(ret, allowlist.Name)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

func (cli *cliAllowLists) listCSV(out io.Writer, allowlists *models.GetAllowlistsResponse) error {
	csvwriter := csv.NewWriter(out)

	err := csvwriter.Write([]string{"name", "description", "created_at", "updated_at", "console_managed", "size"})
	if err != nil {
		return fmt.Errorf("failed to write raw header: %w", err)
	}

	for _, allowlist := range *allowlists {
		createdAt := time.Time(allowlist.CreatedAt).Format(time.RFC3339)
		updatedAt := time.Time(allowlist.UpdatedAt).Format(time.RFC3339)
		consoleManaged := strconv.FormatBool(allowlist.ConsoleManaged)
		itemsCount := strconv.Itoa(len(allowlist.Items))

		err := csvwriter.Write([]string{allowlist.Name, allowlist.Description, createdAt, updatedAt, consoleManaged, itemsCount})
		if err != nil {
			return fmt.Errorf("failed to write raw: %w", err)
		}
	}

	csvwriter.Flush()

	return nil
}

func (cli *cliAllowLists) listCSVContent(out io.Writer, allowlist *models.GetAllowlistResponse) error {
	csvwriter := csv.NewWriter(out)

	err := csvwriter.Write([]string{"name", "description", "value", "comment", "expiration", "created_at", "console_managed"})
	if err != nil {
		return fmt.Errorf("failed to write raw header: %w", err)
	}

	for _, item := range allowlist.Items {
		createdAt := time.Time(item.CreatedAt).Format(time.RFC3339)
		expiration := "never"

		if !time.Time(item.Expiration).IsZero() {
			expiration = time.Time(item.Expiration).Format(time.RFC3339)
		}

		err := csvwriter.Write([]string{allowlist.Name, allowlist.Description, item.Value, item.Description, expiration, createdAt, strconv.FormatBool(allowlist.ConsoleManaged)})
		if err != nil {
			return fmt.Errorf("failed to write raw: %w", err)
		}
	}

	csvwriter.Flush()

	return nil
}

func (cli *cliAllowLists) listHuman(out io.Writer, allowlists *models.GetAllowlistsResponse) error {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Name", "Description", "Creation Date", "Updated at", "Managed by Console", "Size"})

	for _, allowlist := range *allowlists {
		t.AppendRow(table.Row{allowlist.Name, allowlist.Description, allowlist.CreatedAt, allowlist.UpdatedAt, allowlist.ConsoleManaged, len(allowlist.Items)})
	}

	_, err := io.WriteString(out, t.Render()+"\n")
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

func (cli *cliAllowLists) listContentHuman(out io.Writer, allowlist *models.GetAllowlistResponse) error {
	infoTable := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	infoTable.SetTitle("Allowlist: " + allowlist.Name)
	infoTable.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	contentTable := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	contentTable.AppendHeader(table.Row{"Value", "Comment", "Expiration", "Created at"})

	infoTable.AppendRows([]table.Row{
		{"Name", allowlist.Name},
		{"Description", allowlist.Description},
		{"Creation Date", allowlist.CreatedAt},
		{"Updated at", allowlist.UpdatedAt},
		{"Managed by Console", allowlist.ConsoleManaged},
	})

	for _, content := range allowlist.Items {
		expiration := "never"
		if !time.Time(content.Expiration).IsZero() {
			expiration = content.Expiration.String()
		}

		contentTable.AppendRow(table.Row{content.Value, content.Description, expiration, allowlist.CreatedAt})
	}

	_, err := io.WriteString(out, infoTable.Render()+"\n")
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	_, err = io.WriteString(out, contentTable.Render()+"\n")
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

func (cli *cliAllowLists) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "allowlists [action]",
		Short:             "Manage centralized allowlists",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newCreateCmd())
	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newRemoveCmd())
	cmd.AddCommand(cli.newInspectCmd())

	return cmd
}

func (cli *cliAllowLists) newCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create [allowlist_name]",
		Example: "cscli allowlists create my_allowlist -d 'my allowlist description'",
		Short:   "Create a new allowlist",
		Args:    cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			cfg := cli.cfg()

			if err = require.LAPI(cfg); err != nil {
				return err
			}

			cli.db, err = require.DBClient(cmd.Context(), cfg.DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: cli.create,
	}

	flags := cmd.Flags()

	flags.StringP("description", "d", "", "description of the allowlist")

	_ = cmd.MarkFlagRequired("description")

	return cmd
}

func (cli *cliAllowLists) create(cmd *cobra.Command, args []string) error {
	name := args[0]
	description := cmd.Flag("description").Value.String()

	_, err := cli.db.CreateAllowList(cmd.Context(), name, description, "", false)

	if err != nil {
		return err
	}

	log.Infof("allowlist '%s' created successfully", name)

	return nil
}

func (cli *cliAllowLists) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Example: `cscli allowlists list`,
		Short:   "List all allowlists",
		Args:    cobra.NoArgs,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := cfg.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			apiURL, err := url.Parse(cfg.API.Client.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url: %w", err)
			}

			cli.client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     cfg.API.Client.Credentials.Login,
				Password:      strfmt.Password(cfg.API.Client.Credentials.Password),
				URL:           apiURL,
				VersionPrefix: "v1",
			})
			if err != nil {
				return fmt.Errorf("creating api client: %w", err)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.list(cmd, color.Output)
		},
	}

	return cmd
}

func (cli *cliAllowLists) list(cmd *cobra.Command, out io.Writer) error {
	allowlists, _, err := cli.client.Allowlists.List(cmd.Context(), apiclient.AllowlistListOpts{WithContent: true})
	if err != nil {
		return err
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		return cli.listHuman(out, allowlists)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(allowlists); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		return cli.listCSV(out, allowlists)
	}

	return nil
}

func (cli *cliAllowLists) newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "delete [allowlist_name]",
		Short:             "Delete an allowlist",
		Example:           `cscli allowlists delete my_allowlist`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cli.validAllowlists,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			cfg := cli.cfg()

			if err = require.LAPI(cfg); err != nil {
				return err
			}

			cli.db, err = require.DBClient(cmd.Context(), cfg.DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: cli.delete,
	}

	return cmd
}

func (cli *cliAllowLists) delete(cmd *cobra.Command, args []string) error {
	name := args[0]

	list, err := cli.db.GetAllowList(cmd.Context(), name, false)
	if err != nil {
		return err
	}

	if list == nil {
		return fmt.Errorf("allowlist %s not found", name)
	}

	if list.FromConsole {
		return fmt.Errorf("allowlist %s is managed by console, cannot delete with cscli", name)
	}

	err = cli.db.DeleteAllowList(cmd.Context(), name, false)
	if err != nil {
		return err
	}

	log.Infof("allowlist '%s' deleted successfully", name)

	return nil
}

func (cli *cliAllowLists) newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "add [allowlist_name] --value [value] [-e expiration] [-d comment]",
		Short:             "Add content an allowlist",
		Example:           `cscli allowlists add my_allowlist --value 1.2.3.4 --value 2.3.4.5 -e 1h -d "my comment"`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cli.validAllowlists,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			cfg := cli.cfg()

			if err = require.LAPI(cfg); err != nil {
				return err
			}

			cli.db, err = require.DBClient(cmd.Context(), cfg.DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: cli.add,
	}

	flags := cmd.Flags()

	flags.StringSliceP("value", "v", nil, "value to add to the allowlist")
	flags.StringP("expiration", "e", "", "expiration duration")
	flags.StringP("comment", "d", "", "comment for the value")

	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func (cli *cliAllowLists) add(cmd *cobra.Command, args []string) error {
	var expiration time.Duration

	name := args[0]
	values, err := cmd.Flags().GetStringSlice("value")
	comment := cmd.Flag("comment").Value.String()

	if err != nil {
		return err
	}

	expirationStr := cmd.Flag("expiration").Value.String()

	if expirationStr != "" {
		expiration, err = cstime.ParseDuration(expirationStr)
		if err != nil {
			return err
		}
	}

	allowlist, err := cli.db.GetAllowList(cmd.Context(), name, true)
	if err != nil {
		return fmt.Errorf("unable to get allowlist: %w", err)
	}

	if allowlist.FromConsole {
		return fmt.Errorf("allowlist %s is managed by console, cannot update with cscli", name)
	}

	toAdd := make([]*models.AllowlistItem, 0)

	for _, v := range values {
		found := false

		for _, item := range allowlist.Edges.AllowlistItems {
			if item.Value == v {
				found = true

				log.Warnf("value %s already in allowlist", v)

				break
			}
		}

		if !found {
			expTS := time.Time{}
			if expiration != 0 {
				expTS = time.Now().UTC().Add(expiration)
			}

			toAdd = append(toAdd, &models.AllowlistItem{Value: v, Description: comment, Expiration: strfmt.DateTime(expTS)})
		}
	}

	if len(toAdd) == 0 {
		log.Warn("no value to add to allowlist")
		return nil
	}

	log.Debugf("adding %d values to allowlist %s", len(toAdd), name)

	err = cli.db.AddToAllowlist(cmd.Context(), allowlist, toAdd)
	if err != nil {
		return fmt.Errorf("unable to add values to allowlist: %w", err)
	}

	return nil
}

func (cli *cliAllowLists) newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "inspect [allowlist_name]",
		Example:           `cscli allowlists inspect my_allowlist`,
		Short:             "Inspect an allowlist",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cli.validAllowlistsWithConsole,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := cfg.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			apiURL, err := url.Parse(cfg.API.Client.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url: %w", err)
			}

			cli.client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     cfg.API.Client.Credentials.Login,
				Password:      strfmt.Password(cfg.API.Client.Credentials.Password),
				URL:           apiURL,
				VersionPrefix: "v1",
			})
			if err != nil {
				return fmt.Errorf("creating api client: %w", err)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.inspect(cmd, args, color.Output)
		},
	}

	return cmd
}

func (cli *cliAllowLists) inspect(cmd *cobra.Command, args []string, out io.Writer) error {
	name := args[0]

	allowlist, _, err := cli.client.Allowlists.Get(cmd.Context(), name, apiclient.AllowlistGetOpts{WithContent: true})
	if err != nil {
		return fmt.Errorf("unable to get allowlist: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		return cli.listContentHuman(out, allowlist)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(allowlist); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		return cli.listCSVContent(out, allowlist)
	}

	return nil
}

func (cli *cliAllowLists) newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "remove [allowlist_name] --value [value]",
		Short:             "remove content from an allowlist",
		Example:           `cscli allowlists remove my_allowlist --value 1.2.3.4 --value 2.3.4.5"`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cli.validAllowlists,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			cfg := cli.cfg()

			if err = require.LAPI(cfg); err != nil {
				return err
			}

			cli.db, err = require.DBClient(cmd.Context(), cfg.DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: cli.remove,
	}

	flags := cmd.Flags()

	flags.StringSliceP("value", "v", nil, "value to remove from the allowlist")

	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func (cli *cliAllowLists) remove(cmd *cobra.Command, args []string) error {
	name := args[0]

	values, err := cmd.Flags().GetStringSlice("value")
	if err != nil {
		return err
	}

	allowlist, err := cli.db.GetAllowList(cmd.Context(), name, true)
	if err != nil {
		return fmt.Errorf("unable to get allowlist: %w", err)
	}

	if allowlist.FromConsole {
		return fmt.Errorf("allowlist %s is managed by console, cannot update with cscli", name)
	}

	toRemove := make([]string, 0)

	for _, v := range values {
		found := false

		for _, item := range allowlist.Edges.AllowlistItems {
			if item.Value == v {
				found = true
				break
			}
		}

		if found {
			toRemove = append(toRemove, v)
		}
	}

	if len(toRemove) == 0 {
		log.Warn("no value to remove from allowlist")
	}

	log.Debugf("removing %d values from allowlist %s", len(toRemove), name)

	nbDeleted, err := cli.db.RemoveFromAllowlist(cmd.Context(), allowlist, toRemove...)
	if err != nil {
		return fmt.Errorf("unable to remove values from allowlist: %w", err)
	}

	log.Infof("removed %d values from allowlist %s", nbDeleted, name)

	return nil
}
