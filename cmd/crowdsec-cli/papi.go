package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/database"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
)

type cliPapi struct {}

func NewCLIPapi() *cliPapi {
	return &cliPapi{}
}

func (cli cliPapi) NewCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:               "papi [action]",
		Short:             "Manage interaction with Polling API (PAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := require.LAPI(csConfig); err != nil {
				return err
			}
			if err := require.CAPI(csConfig); err != nil {
				return err
			}
			if err := require.PAPI(csConfig); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.AddCommand(cli.NewStatusCmd())
	cmd.AddCommand(cli.NewSyncCmd())

	return cmd
}

func (cli cliPapi) NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Get status of the Polling API",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to initialize database client : %s", err)
			}

			apic, err := apiserver.NewAPIC(csConfig.API.Server.OnlineClient, dbClient, csConfig.API.Server.ConsoleConfig, csConfig.API.Server.CapiWhitelists)

			if err != nil {
				log.Fatalf("unable to initialize API client : %s", err)
			}

			papi, err := apiserver.NewPAPI(apic, dbClient, csConfig.API.Server.ConsoleConfig, log.GetLevel())

			if err != nil {
				log.Fatalf("unable to initialize PAPI client : %s", err)
			}

			perms, err := papi.GetPermissions()

			if err != nil {
				log.Fatalf("unable to get PAPI permissions: %s", err)
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
		},
	}

	return cmd
}

func (cli cliPapi) NewSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sync",
		Short:             "Sync with the Polling API, pulling all non-expired orders for the instance",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			t := tomb.Tomb{}
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to initialize database client : %s", err)
			}

			apic, err := apiserver.NewAPIC(csConfig.API.Server.OnlineClient, dbClient, csConfig.API.Server.ConsoleConfig, csConfig.API.Server.CapiWhitelists)

			if err != nil {
				log.Fatalf("unable to initialize API client : %s", err)
			}

			t.Go(apic.Push)

			papi, err := apiserver.NewPAPI(apic, dbClient, csConfig.API.Server.ConsoleConfig, log.GetLevel())

			if err != nil {
				log.Fatalf("unable to initialize PAPI client : %s", err)
			}
			t.Go(papi.SyncDecisions)

			err = papi.PullOnce(time.Time{}, true)

			if err != nil {
				log.Fatalf("unable to sync decisions: %s", err)
			}

			log.Infof("Sending acknowledgements to CAPI")

			apic.Shutdown()
			papi.Shutdown()
			t.Wait()
			time.Sleep(5 * time.Second) //FIXME: the push done by apic.Push is run inside a sub goroutine, sleep to make sure it's done

		},
	}

	return cmd
}
