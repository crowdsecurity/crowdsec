package clibouncer

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/ask"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type configGetter = func() *csconfig.Config

type cliBouncers struct {
	db  *database.Client
	cfg configGetter
}

func New(cfg configGetter) *cliBouncers {
	return &cliBouncers{
		cfg: cfg,
	}
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
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newPruneCmd())
	cmd.AddCommand(cli.newInspectCmd())

	return cmd
}

func (cli *cliBouncers) listHuman(out io.Writer, bouncers ent.Bouncers) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer
	t.AppendHeader(table.Row{"Name", "IP Address", "Valid", "Last API pull", "Type", "Version", "Auth Type"})

	for _, b := range bouncers {
		revoked := emoji.CheckMark
		if b.Revoked {
			revoked = emoji.Prohibited
		}

		lastPull := ""
		if b.LastPull != nil {
			lastPull = b.LastPull.Format(time.RFC3339)
		}

		t.AppendRow(table.Row{b.Name, b.IPAddress, revoked, lastPull, b.Type, b.Version, b.AuthType})
	}

	io.WriteString(out, t.Render()+"\n")
}

// bouncerInfo contains only the data we want for inspect/list
type bouncerInfo struct {
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Name         string     `json:"name"`
	Revoked      bool       `json:"revoked"`
	IPAddress    string     `json:"ip_address"`
	Type         string     `json:"type"`
	Version      string     `json:"version"`
	LastPull     *time.Time `json:"last_pull"`
	AuthType     string     `json:"auth_type"`
	OS           string     `json:"os,omitempty"`
	Featureflags []string   `json:"featureflags,omitempty"`
}

func newBouncerInfo(b *ent.Bouncer) bouncerInfo {
	return bouncerInfo{
		CreatedAt:    b.CreatedAt,
		UpdatedAt:    b.UpdatedAt,
		Name:         b.Name,
		Revoked:      b.Revoked,
		IPAddress:    b.IPAddress,
		Type:         b.Type,
		Version:      b.Version,
		LastPull:     b.LastPull,
		AuthType:     b.AuthType,
		OS:           clientinfo.GetOSNameAndVersion(b),
		Featureflags: clientinfo.GetFeatureFlagList(b),
	}
}

func (cli *cliBouncers) listCSV(out io.Writer, bouncers ent.Bouncers) error {
	csvwriter := csv.NewWriter(out)

	if err := csvwriter.Write([]string{"name", "ip", "revoked", "last_pull", "type", "version", "auth_type"}); err != nil {
		return fmt.Errorf("failed to write raw header: %w", err)
	}

	for _, b := range bouncers {
		valid := "validated"
		if b.Revoked {
			valid = "pending"
		}

		lastPull := ""
		if b.LastPull != nil {
			lastPull = b.LastPull.Format(time.RFC3339)
		}

		if err := csvwriter.Write([]string{b.Name, b.IPAddress, valid, lastPull, b.Type, b.Version, b.AuthType}); err != nil {
			return fmt.Errorf("failed to write raw: %w", err)
		}
	}

	csvwriter.Flush()

	return nil
}

func (cli *cliBouncers) List(ctx context.Context, out io.Writer, db *database.Client) error {
	// XXX: must use the provided db object, the one in the struct might be nil
	// (calling List directly skips the PersistentPreRunE)

	bouncers, err := db.ListBouncers(ctx)
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		cli.listHuman(out, bouncers)
	case "json":
		info := make([]bouncerInfo, 0, len(bouncers))
		for _, b := range bouncers {
			info = append(info, newBouncerInfo(b))
		}

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(info); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		return cli.listCSV(out, bouncers)
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.List(cmd.Context(), color.Output, cli.db)
		},
	}

	return cmd
}

func (cli *cliBouncers) add(ctx context.Context, bouncerName string, key string) error {
	var err error

	keyLength := 32

	if key == "" {
		key, err = middlewares.GenerateAPIKey(keyLength)
		if err != nil {
			return fmt.Errorf("unable to generate api key: %w", err)
		}
	}

	_, err = cli.db.CreateBouncer(ctx, bouncerName, "", middlewares.HashSHA512(key), types.ApiKeyAuthType)
	if err != nil {
		return fmt.Errorf("unable to create bouncer: %w", err)
	}

	switch cli.cfg().Cscli.Output {
	case "human":
		fmt.Printf("API key for '%s':\n\n", bouncerName)
		fmt.Printf("   %s\n\n", key)
		fmt.Print("Please keep this key since you will not be able to retrieve it!\n")
	case "raw":
		fmt.Print(key)
	case "json":
		j, err := json.Marshal(key)
		if err != nil {
			return errors.New("unable to serialize api key")
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
			return cli.add(cmd.Context(), args[0], key)
		},
	}

	flags := cmd.Flags()
	flags.StringP("length", "l", "", "length of the api key")
	_ = flags.MarkDeprecated("length", "use --key instead")
	flags.StringVarP(&key, "key", "k", "", "api key for the bouncer")

	return cmd
}

// validBouncerID returns a list of bouncer IDs for command completion
func (cli *cliBouncers) validBouncerID(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error

	cfg := cli.cfg()
	ctx := cmd.Context()

	// need to load config and db because PersistentPreRunE is not called for completions

	if err = require.LAPI(cfg); err != nil {
		cobra.CompError("unable to list bouncers " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cli.db, err = require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		cobra.CompError("unable to list bouncers " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	bouncers, err := cli.db.ListBouncers(ctx)
	if err != nil {
		cobra.CompError("unable to list bouncers " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ret := []string{}

	for _, bouncer := range bouncers {
		if strings.Contains(bouncer.Name, toComplete) && !slices.Contains(args, bouncer.Name) {
			ret = append(ret, bouncer.Name)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}

func (cli *cliBouncers) delete(ctx context.Context, bouncers []string, ignoreMissing bool) error {
	for _, bouncerID := range bouncers {
		if err := cli.db.DeleteBouncer(ctx, bouncerID); err != nil {
			var notFoundErr *database.BouncerNotFoundError
			if ignoreMissing && errors.As(err, &notFoundErr) {
				return nil
			}

			return fmt.Errorf("unable to delete bouncer: %w", err)
		}

		log.Infof("bouncer '%s' deleted successfully", bouncerID)
	}

	return nil
}

func (cli *cliBouncers) newDeleteCmd() *cobra.Command {
	var ignoreMissing bool

	cmd := &cobra.Command{
		Use:               "delete MyBouncerName",
		Short:             "delete bouncer(s) from the database",
		Example:           `cscli bouncers delete "bouncer1" "bouncer2"`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"remove"},
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validBouncerID,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.delete(cmd.Context(), args, ignoreMissing)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&ignoreMissing, "ignore-missing", false, "don't print errors if one or more bouncers don't exist")

	return cmd
}

func (cli *cliBouncers) prune(ctx context.Context, duration time.Duration, force bool) error {
	if duration < 2*time.Minute {
		if yes, err := ask.YesNo(
			"The duration you provided is less than 2 minutes. "+
				"This may remove active bouncers. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	bouncers, err := cli.db.QueryBouncersInactiveSince(ctx, time.Now().UTC().Add(-duration))
	if err != nil {
		return fmt.Errorf("unable to query bouncers: %w", err)
	}

	if len(bouncers) == 0 {
		fmt.Println("No bouncers to prune.")
		return nil
	}

	cli.listHuman(color.Output, bouncers)

	if !force {
		if yes, err := ask.YesNo(
			"You are about to PERMANENTLY remove the above bouncers from the database. "+
				"These will NOT be recoverable. Continue?", false); err != nil {
			return err
		} else if !yes {
			fmt.Println("User aborted prune. No changes were made.")
			return nil
		}
	}

	deleted, err := cli.db.BulkDeleteBouncers(ctx, bouncers)
	if err != nil {
		return fmt.Errorf("unable to prune bouncers: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully deleted %d bouncers\n", deleted)

	return nil
}

func (cli *cliBouncers) newPruneCmd() *cobra.Command {
	var (
		duration time.Duration
		force    bool
	)

	const defaultDuration = 60 * time.Minute

	cmd := &cobra.Command{
		Use:               "prune",
		Short:             "prune multiple bouncers from the database",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Example: `cscli bouncers prune -d 45m
cscli bouncers prune -d 45m --force`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.prune(cmd.Context(), duration, force)
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", defaultDuration, "duration of time since last pull")
	flags.BoolVar(&force, "force", false, "force prune without asking for confirmation")

	return cmd
}

func (cli *cliBouncers) inspectHuman(out io.Writer, bouncer *ent.Bouncer) {
	t := cstable.NewLight(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Bouncer: " + bouncer.Name)

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	lastPull := ""
	if bouncer.LastPull != nil {
		lastPull = bouncer.LastPull.String()
	}

	t.AppendRows([]table.Row{
		{"Created At", bouncer.CreatedAt},
		{"Last Update", bouncer.UpdatedAt},
		{"Revoked?", bouncer.Revoked},
		{"IP Address", bouncer.IPAddress},
		{"Type", bouncer.Type},
		{"Version", bouncer.Version},
		{"Last Pull", lastPull},
		{"Auth type", bouncer.AuthType},
		{"OS", clientinfo.GetOSNameAndVersion(bouncer)},
	})

	for _, ff := range clientinfo.GetFeatureFlagList(bouncer) {
		t.AppendRow(table.Row{"Feature Flags", ff})
	}

	io.WriteString(out, t.Render()+"\n")
}

func (cli *cliBouncers) inspect(bouncer *ent.Bouncer) error {
	out := color.Output
	outputFormat := cli.cfg().Cscli.Output

	switch outputFormat {
	case "human":
		cli.inspectHuman(out, bouncer)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(newBouncerInfo(bouncer)); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}

func (cli *cliBouncers) newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "inspect [bouncer_name]",
		Short:             "inspect a bouncer by name",
		Example:           `cscli bouncers inspect "bouncer1"`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validBouncerID,
		RunE: func(cmd *cobra.Command, args []string) error {
			bouncerName := args[0]

			b, err := cli.db.Ent.Bouncer.Query().
				Where(bouncer.Name(bouncerName)).
				Only(cmd.Context())
			if err != nil {
				return fmt.Errorf("unable to read bouncer data '%s': %w", bouncerName, err)
			}

			return cli.inspect(b)
		},
	}

	return cmd
}
