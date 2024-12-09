package cliallowlists

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
		if strings.Contains(allowlist.Name, toComplete) && !slices.Contains(args, allowlist.Name) {
			ret = append(ret, allowlist.Name)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

func (cli *cliAllowLists) listHuman(out io.Writer, allowlists *models.GetAllowlistsResponse) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Name", "Description", "Creation Date", "Updated at", "Managed by Console", "Size"})

	for _, allowlist := range *allowlists {
		t.AppendRow(table.Row{allowlist.Name, allowlist.Description, allowlist.CreatedAt, allowlist.UpdatedAt, allowlist.ConsoleManaged, len(allowlist.Items)})
	}

	io.WriteString(out, t.Render()+"\n")
}

func (cli *cliAllowLists) listContentHuman(out io.Writer, allowlist *models.GetAllowlistResponse) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Value", "Comment", "Expiration", "Created at"})

	for _, content := range allowlist.Items {
		expiration := "never"
		if !time.Time(content.Expiration).IsZero() {
			expiration = content.Expiration.String()
		}
		t.AppendRow(table.Row{content.Value, content.Description, expiration, allowlist.CreatedAt})
	}

	io.WriteString(out, t.Render()+"\n")
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

	cmd.MarkFlagRequired("description")

	return cmd
}

func (cli *cliAllowLists) create(cmd *cobra.Command, args []string) error {
	name := args[0]
	description := cmd.Flag("description").Value.String()

	_, err := cli.db.CreateAllowList(cmd.Context(), name, description, false)

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
		cli.listHuman(out, allowlists)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(allowlists); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		//return cli.listCSV(out, allowlists)
	}

	return nil
}

func (cli *cliAllowLists) newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [allowlist_name]",
		Short:   "Delete an allowlist",
		Example: `cscli allowlists delete my_allowlist`,
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
		Use:     "add [allowlist_name] --value [value] [-e expiration] [-d comment]",
		Short:   "Add content an allowlist",
		Example: `cscli allowlists add my_allowlist --value 1.2.3.4 --value 2.3.4.5 -e 1h -d "my comment"`,
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
		RunE: cli.add,
	}

	flags := cmd.Flags()

	flags.StringSliceP("value", "v", nil, "value to add to the allowlist")
	flags.StringP("expiration", "e", "", "expiration duration")
	flags.StringP("comment", "d", "", "comment for the value")

	cmd.MarkFlagRequired("value")

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
		//FIXME: handle days (and maybe more ?)
		expiration, err = time.ParseDuration(expirationStr)

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
			toAdd = append(toAdd, &models.AllowlistItem{Value: v, Description: comment, Expiration: strfmt.DateTime(time.Now().UTC().Add(expiration))})
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
		Use:     "inspect [allowlist_name]",
		Example: `cscli allowlists inspect my_allowlist`,
		Short:   "Inspect an allowlist",
		Args:    cobra.ExactArgs(1),
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
		cli.listContentHuman(out, allowlist)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(allowlist); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		//return cli.listCSV(out, allowlists)
	}

	return nil
}

func (cli *cliAllowLists) newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove [allowlist_name] --value [value]",
		Short:   "remove content from an allowlist",
		Example: `cscli allowlists remove my_allowlist --value 1.2.3.4 --value 2.3.4.5"`,
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
		RunE: cli.remove,
	}

	flags := cmd.Flags()

	flags.StringSliceP("value", "v", nil, "value to remove from the allowlist")

	cmd.MarkFlagRequired("value")

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