package main

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/database"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
)

type cliPapi struct {
	cfg configGetter
}

func NewCLIPapi(getconfig configGetter) *cliPapi {
	return &cliPapi{
		cfg: getconfig,
	}
}

func (cli *cliPapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "papi [action]",
		Short:             "Manage interaction with Polling API (PAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg := cli.cfg()
			if err := require.LAPI(cfg); err != nil {
				return err
			}
			if err := require.CAPI(cfg); err != nil {
				return err
			}
			if err := require.PAPI(cfg); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.AddCommand(cli.NewStatusCmd())
	cmd.AddCommand(cli.NewSyncCmd())

	return cmd
}

func (cli *cliPapi) NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Get status of the Polling API",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg := cli.cfg()
			dbClient, err = database.NewClient(cfg.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to initialize database client: %s", err)
			}

			apic, err := apiserver.NewAPIC(cfg.API.Server.OnlineClient, dbClient, cfg.API.Server.ConsoleConfig, cfg.API.Server.CapiWhitelists)

			if err != nil {
				return fmt.Errorf("unable to initialize API client: %s", err)
			}

			papi, err := apiserver.NewPAPI(apic, dbClient, cfg.API.Server.ConsoleConfig, log.GetLevel())

			if err != nil {
				return fmt.Errorf("unable to initialize PAPI client: %s", err)
			}

			perms, err := papi.GetPermissions()

			if err != nil {
				return fmt.Errorf("unable to get PAPI permissions: %s", err)
			}
			var lastTimestampStr *string
			lastTimestampStr, err = dbClient.GetConfigItem(apiserver.PapiPullKey)
			if err != nil {
				lastTimestampStr = ptr.Of("never")
			}
			log.Infof("You can successfully interact with Polling API (PAPI)")
			log.Infof("Console plan: %s", perms.Plan)
			log.Infof("Last order received: %s", *lastTimestampStr)

			log.Infof("PAPI subscriptions:")
			for _, sub := range perms.Categories {
				log.Infof(" - %s", sub)
			}

			return nil
		},
	}

	return cmd
}

func (cli *cliPapi) NewSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sync",
		Short:             "Sync with the Polling API, pulling all non-expired orders for the instance",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg := cli.cfg()
			t := tomb.Tomb{}

			dbClient, err = database.NewClient(cfg.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to initialize database client: %s", err)
			}

			apic, err := apiserver.NewAPIC(cfg.API.Server.OnlineClient, dbClient, cfg.API.Server.ConsoleConfig, cfg.API.Server.CapiWhitelists)
			if err != nil {
				return fmt.Errorf("unable to initialize API client: %s", err)
			}

			t.Go(apic.Push)

			papi, err := apiserver.NewPAPI(apic, dbClient, cfg.API.Server.ConsoleConfig, log.GetLevel())
			if err != nil {
				return fmt.Errorf("unable to initialize PAPI client: %s", err)
			}

			t.Go(papi.SyncDecisions)

			err = papi.PullOnce(time.Time{}, true)

			if err != nil {
				return fmt.Errorf("unable to sync decisions: %s", err)
			}

			log.Infof("Sending acknowledgements to CAPI")

			apic.Shutdown()
			papi.Shutdown()
			t.Wait()
			time.Sleep(5 * time.Second) //FIXME: the push done by apic.Push is run inside a sub goroutine, sleep to make sure it's done

			return nil
		},
	}

	return cmd
}
