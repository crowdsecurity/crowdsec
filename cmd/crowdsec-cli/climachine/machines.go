package climachine

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

type cliMachines struct {
	db  *database.Client
	cfg configGetter
}

func New(cfg configGetter) *cliMachines {
	return &cliMachines{
		cfg: cfg,
	}
}

func (cli *cliMachines) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machines [action]",
		Short: "Manage local API machines [requires local API]",
		Long: `To list/add/delete/validate/prune machines.
Note: This command requires database direct access, so is intended to be run on the local API machine.
`,
		Example:           `cscli machines [action]`,
		DisableAutoGenTag: true,
		Aliases:           []string{"machine"},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if err = require.LAPI(cli.cfg()); err != nil {
				return err
			}
			cli.db, err = require.DBClient(cmd.Context(), cli.cfg().DbConfig)
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newValidateCmd())
	cmd.AddCommand(cli.newPruneCmd())
	cmd.AddCommand(cli.newInspectCmd())

	return cmd
}

// machineInfo contains only the data we want for inspect/list: no hub status, scenarios, edges, etc.
type machineInfo struct {
	CreatedAt     time.Time        `json:"created_at,omitempty"`
	UpdatedAt     time.Time        `json:"updated_at,omitempty"`
	LastPush      *time.Time       `json:"last_push,omitempty"`
	LastHeartbeat *time.Time       `json:"last_heartbeat,omitempty"`
	MachineId     string           `json:"machineId,omitempty"`
	IpAddress     string           `json:"ipAddress,omitempty"`
	Version       string           `json:"version,omitempty"`
	IsValidated   bool             `json:"isValidated,omitempty"`
	AuthType      string           `json:"auth_type"`
	OS            string           `json:"os,omitempty"`
	Featureflags  []string         `json:"featureflags,omitempty"`
	Datasources   map[string]int64 `json:"datasources,omitempty"`
}

func newMachineInfo(m *ent.Machine) machineInfo {
	return machineInfo{
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
		LastPush:      m.LastPush,
		LastHeartbeat: m.LastHeartbeat,
		MachineId:     m.MachineId,
		IpAddress:     m.IpAddress,
		Version:       m.Version,
		IsValidated:   m.IsValidated,
		AuthType:      m.AuthType,
		OS:            clientinfo.GetOSNameAndVersion(m),
		Featureflags:  clientinfo.GetFeatureFlagList(m),
		Datasources:   m.Datasources,
	}
}

// validMachineID returns a list of machine IDs for command completion
func (cli *cliMachines) validMachineID(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var err error

	cfg := cli.cfg()
	ctx := cmd.Context()

	// need to load config and db because PersistentPreRunE is not called for completions

	if err = require.LAPI(cfg); err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cli.db, err = require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	machines, err := cli.db.ListMachines(ctx)
	if err != nil {
		cobra.CompError("unable to list machines " + err.Error())
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ret := []string{}

	for _, machine := range machines {
		if strings.Contains(machine.MachineId, toComplete) && !slices.Contains(args, machine.MachineId) {
			ret = append(ret, machine.MachineId)
		}
	}

	return ret, cobra.ShellCompDirectiveNoFileComp
}
