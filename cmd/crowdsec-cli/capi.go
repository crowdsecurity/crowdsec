package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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

type cliCapi struct {
	cfg configGetter
}

func NewCLICapi(cfg configGetter) *cliCapi {
	return &cliCapi{
		cfg: cfg,
	}
}

func (cli *cliCapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "capi [action]",
		Short:             "Manage interaction with Central API (CAPI)",
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

			return nil
		},
	}

	cmd.AddCommand(cli.newRegisterCmd())
	cmd.AddCommand(cli.newStatusCmd())

	return cmd
}

func (cli *cliCapi) register(capiUserPrefix string, outputFile string) error {
	cfg := cli.cfg()

	capiUser, err := generateID(capiUserPrefix)
	if err != nil {
		return fmt.Errorf("unable to generate machine id: %w", err)
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

	log.Infof("Successfully registered to Central API (CAPI)")

	var dumpFile string

	switch {
	case outputFile != "":
		dumpFile = outputFile
	case cfg.API.Server.OnlineClient.CredentialsFilePath != "":
		dumpFile = cfg.API.Server.OnlineClient.CredentialsFilePath
	default:
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

		log.Infof("Central API credentials written to '%s'", dumpFile)
	} else {
		fmt.Println(string(apiConfigDump))
	}

	log.Warning(ReloadMessage())

	return nil
}

func (cli *cliCapi) newRegisterCmd() *cobra.Command {
	var (
		capiUserPrefix string
		outputFile     string
	)

	cmd := &cobra.Command{
		Use:               "register",
		Short:             "Register to Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.register(capiUserPrefix, outputFile)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmd.Flags().StringVar(&capiUserPrefix, "schmilblick", "", "set a schmilblick (use in tests only)")

	if err := cmd.Flags().MarkHidden("schmilblick"); err != nil {
		log.Fatalf("failed to hide flag: %s", err)
	}

	return cmd
}

func (cli *cliCapi) status() error {
	cfg := cli.cfg()

	if err := require.CAPIRegistered(cfg); err != nil {
		return err
	}

	password := strfmt.Password(cfg.API.Server.OnlineClient.Credentials.Password)

	apiurl, err := url.Parse(cfg.API.Server.OnlineClient.Credentials.URL)
	if err != nil {
		return fmt.Errorf("parsing api url ('%s'): %w", cfg.API.Server.OnlineClient.Credentials.URL, err)
	}

	hub, err := require.Hub(cfg, nil, nil)
	if err != nil {
		return err
	}

	scenarios, err := hub.GetInstalledNamesByType(cwhub.SCENARIOS)
	if err != nil {
		return fmt.Errorf("failed to get scenarios: %w", err)
	}

	if len(scenarios) == 0 {
		return errors.New("no scenarios installed, abort")
	}

	Client, err = apiclient.NewDefaultClient(apiurl, CAPIURLPrefix, fmt.Sprintf("crowdsec/%s", version.String()), nil)
	if err != nil {
		return fmt.Errorf("init default client: %w", err)
	}

	t := models.WatcherAuthRequest{
		MachineID: &cfg.API.Server.OnlineClient.Credentials.Login,
		Password:  &password,
		Scenarios: scenarios,
	}

	fmt.Printf("Loaded credentials from %s\n", cfg.API.Server.OnlineClient.CredentialsFilePath)
	fmt.Printf("Trying to authenticate with username %s on %s\n", cfg.API.Server.OnlineClient.Credentials.Login, apiurl)

	_, _, err = Client.Auth.AuthenticateWatcher(context.Background(), t)
	if err != nil {
		return fmt.Errorf("failed to authenticate to Central API (CAPI): %w", err)
	}

	fmt.Println("You can successfully interact with Central API (CAPI)")

	return nil
}

func (cli *cliCapi) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Check status with the Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.status()
		},
	}

	return cmd
}
