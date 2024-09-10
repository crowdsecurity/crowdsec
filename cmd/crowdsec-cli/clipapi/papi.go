package clipapi

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type configGetter func() *csconfig.Config

type cliPapi struct {
	cfg configGetter
}

func New(cfg configGetter) *cliPapi {
	return &cliPapi{
		cfg: cfg,
	}
}

func (cli *cliPapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "papi [action]",
		Short:             "Manage interaction with Polling API (PAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := require.LAPI(cfg); err != nil {
				return err
			}
			if err := require.CAPI(cfg); err != nil {
				return err
			}

			return require.PAPI(cfg)
		},
	}

	cmd.AddCommand(cli.newStatusCmd())
	cmd.AddCommand(cli.newSyncCmd())

	return cmd
}

func (cli *cliPapi) status(ctx context.Context, out io.Writer) error {
	cfg := cli.cfg()
	db, err := require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		return err
	}

	apic, err := apiserver.NewAPIC(cfg.API.Server.OnlineClient, db, cfg.API.Server.ConsoleConfig, cfg.API.Server.CapiWhitelists)
	if err != nil {
		return fmt.Errorf("unable to initialize API client: %w", err)
	}

	papi, err := apiserver.NewPAPI(apic, db, cfg.API.Server.ConsoleConfig, log.GetLevel())
	if err != nil {
		return fmt.Errorf("unable to initialize PAPI client: %w", err)
	}

	perms, err := papi.GetPermissions()
	if err != nil {
		return fmt.Errorf("unable to get PAPI permissions: %w", err)
	}
	var lastTimestampStr *string
	lastTimestampStr, err = db.GetConfigItem(apiserver.PapiPullKey)
	if err != nil {
		lastTimestampStr = ptr.Of("never")
	}

	fmt.Fprint(out, "You can successfully interact with Polling API (PAPI)\n")
	fmt.Fprintf(out, "Console plan: %s\n", perms.Plan)
	fmt.Fprintf(out, "Last order received: %s\n", *lastTimestampStr)

	fmt.Fprint(out, "PAPI subscriptions:\n")
	for _, sub := range perms.Categories {
		fmt.Fprintf(out, " - %s\n", sub)
	}

	return nil
}

func (cli *cliPapi) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Get status of the Polling API",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.status(cmd.Context(), color.Output)
		},
	}

	return cmd
}

func (cli *cliPapi) sync(ctx context.Context, out io.Writer) error {
	cfg := cli.cfg()
	t := tomb.Tomb{}

	db, err := require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		return err
	}

	apic, err := apiserver.NewAPIC(cfg.API.Server.OnlineClient, db, cfg.API.Server.ConsoleConfig, cfg.API.Server.CapiWhitelists)
	if err != nil {
		return fmt.Errorf("unable to initialize API client: %w", err)
	}

	t.Go(apic.Push)

	papi, err := apiserver.NewPAPI(apic, db, cfg.API.Server.ConsoleConfig, log.GetLevel())
	if err != nil {
		return fmt.Errorf("unable to initialize PAPI client: %w", err)
	}

	t.Go(papi.SyncDecisions)

	err = papi.PullOnce(time.Time{}, true)
	if err != nil {
		return fmt.Errorf("unable to sync decisions: %w", err)
	}

	log.Infof("Sending acknowledgements to CAPI")

	apic.Shutdown()
	papi.Shutdown()
	t.Wait()
	time.Sleep(5 * time.Second) // FIXME: the push done by apic.Push is run inside a sub goroutine, sleep to make sure it's done

	return nil
}

func (cli *cliPapi) newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sync",
		Short:             "Sync with the Polling API, pulling all non-expired orders for the instance",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.sync(cmd.Context(), color.Output)
		},
	}

	return cmd
}
