package main

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	CAPIBaseURL   = "https://api.crowdsec.net/"
	CAPIURLPrefix = "v3"
)

type cliCapi struct{}

func NewCLICapi() *cliCapi {
	return &cliCapi{}
}

func (cli cliCapi) NewCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:               "capi [action]",
		Short:             "Manage interaction with Central API (CAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := require.LAPI(csConfig); err != nil {
				return err
			}

			if err := require.CAPI(csConfig); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(cli.NewRegisterCmd())
	cmd.AddCommand(cli.NewStatusCmd())

	return cmd
}

func (cli cliCapi) NewRegisterCmd() *cobra.Command {
	var capiUserPrefix string
	var outputFile string

	var cmd = &cobra.Command{
		Use:               "register",
		Short:             "Register to Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			capiUser, err := generateID(capiUserPrefix)
			if err != nil {
				return fmt.Errorf("unable to generate machine id: %s", err)
			}
			password := strfmt.Password(generatePassword(passwordLength))
			apiurl, err := url.Parse(types.CAPIBaseURL)
			if err != nil {
				return fmt.Errorf("unable to parse api url %s: %w", types.CAPIBaseURL, err)
			}
			_, err = apiclient.RegisterClient(&apiclient.Config{
				MachineID:     capiUser,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
				URL:           apiurl,
				VersionPrefix: CAPIURLPrefix,
			}, nil)

			if err != nil {
				return fmt.Errorf("api client register ('%s'): %w", types.CAPIBaseURL, err)
			}
			log.Printf("Successfully registered to Central API (CAPI)")

			var dumpFile string

			if outputFile != "" {
				dumpFile = outputFile
			} else if csConfig.API.Server.OnlineClient.CredentialsFilePath != "" {
				dumpFile = csConfig.API.Server.OnlineClient.CredentialsFilePath
			} else {
				dumpFile = ""
			}
			apiCfg := csconfig.ApiCredentialsCfg{
				Login:    capiUser,
				Password: password.String(),
				URL:      types.CAPIBaseURL,
			}
			apiConfigDump, err := yaml.Marshal(apiCfg)
			if err != nil {
				return fmt.Errorf("unable to marshal api credentials: %w", err)
			}
			if dumpFile != "" {
				err = os.WriteFile(dumpFile, apiConfigDump, 0o600)
				if err != nil {
					return fmt.Errorf("write api credentials in '%s' failed: %w", dumpFile, err)
				}
				log.Printf("Central API credentials written to '%s'", dumpFile)
			} else {
				fmt.Printf("%s\n", string(apiConfigDump))
			}

			log.Warning(ReloadMessage())

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmd.Flags().StringVar(&capiUserPrefix, "schmilblick", "", "set a schmilblick (use in tests only)")
	if err := cmd.Flags().MarkHidden("schmilblick"); err != nil {
		log.Fatalf("failed to hide flag: %s", err)
	}

	return cmd
}

func (cli cliCapi) NewStatusCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:               "status",
		Short:             "Check status with the Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.API.Server.OnlineClient == nil {
				return fmt.Errorf("please provide credentials for the Central API (CAPI) in '%s'", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			}

			if csConfig.API.Server.OnlineClient.Credentials == nil {
				return fmt.Errorf("no credentials for Central API (CAPI) in '%s'", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			}

			password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)

			apiurl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url ('%s'): %w", csConfig.API.Server.OnlineClient.Credentials.URL, err)
			}

			hub, err := require.Hub(csConfig, nil, nil)
			if err != nil {
				return err
			}

			scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
			if err != nil {
				return fmt.Errorf("failed to get scenarios: %w", err)
			}

			if len(scenarios) == 0 {
				return fmt.Errorf("no scenarios installed, abort")
			}

			Client, err = apiclient.NewDefaultClient(apiurl, CAPIURLPrefix, fmt.Sprintf("crowdsec/%s", version.String()), nil)
			if err != nil {
				return fmt.Errorf("init default client: %w", err)
			}

			t := models.WatcherAuthRequest{
				MachineID: &csConfig.API.Server.OnlineClient.Credentials.Login,
				Password:  &password,
				Scenarios: scenarios,
			}

			log.Infof("Loaded credentials from %s", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			log.Infof("Trying to authenticate with username %s on %s", csConfig.API.Server.OnlineClient.Credentials.Login, apiurl)

			_, _, err = Client.Auth.AuthenticateWatcher(context.Background(), t)
			if err != nil {
				return fmt.Errorf("failed to authenticate to Central API (CAPI): %w", err)
			}
			log.Infof("You can successfully interact with Central API (CAPI)")

			return nil
		},
	}

	return cmd
}
