package clibouncer

import (
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
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
	AutoCreated  bool       `json:"auto_created"`
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
		AutoCreated:  b.AutoCreated,
	}
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
