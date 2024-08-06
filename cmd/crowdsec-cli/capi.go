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

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
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

			return require.CAPI(cfg)
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
		UserAgent:     cwversion.UserAgent(),
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

	_ = cmd.Flags().MarkHidden("schmilblick")

	return cmd
}

// QueryCAPIStatus checks if the Local API is reachable, and if the credentials are correct. It then checks if the instance is enrolle in the console.
func QueryCAPIStatus(hub *cwhub.Hub, credURL string, login string, password string) (bool, bool, error) {

	apiURL, err := url.Parse(credURL)
	if err != nil {
		return false, false, fmt.Errorf("parsing api url: %w", err)
	}

	itemsForAPI := hub.GetInstalledListForAPI()

	if len(itemsForAPI) == 0 {
		return false, false, errors.New("no scenarios or appsec-rules installed, abort")
	}

	passwd := strfmt.Password(password)

	client, err := apiclient.NewClient(&apiclient.Config{
		MachineID: login,
		Password:  passwd,
		Scenarios: itemsForAPI,
		UserAgent: cwversion.UserAgent(),
		URL:       apiURL,
		//I don't believe papi is neede to check enrollement
		//PapiURL:       papiURL,
		VersionPrefix: "v3",
		UpdateScenario: func() ([]string, error) {
			return itemsForAPI, nil
		},
	})

	if err != nil {
		return false, false, fmt.Errorf("new client api: %w", err)
	}

	pw := strfmt.Password(password)

	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &pw,
		Scenarios: itemsForAPI,
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(context.Background(), t)
	if err != nil {
		return false, false, err
	}

	client.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token

	if client.IsEnrolled() {
		return true, true, nil
	}
	return true, false, nil

}

func (cli *cliCapi) status() error {
	cfg := cli.cfg()

	if err := require.CAPIRegistered(cfg); err != nil {
		return err
	}

	cred := cfg.API.Server.OnlineClient.Credentials

	hub, err := require.Hub(cfg, nil, nil)
	if err != nil {
		return err
	}

	log.Infof("Loaded credentials from %s", cfg.API.Server.OnlineClient.CredentialsFilePath)
	log.Infof("Trying to authenticate with username %s on %s", cred.Login, cred.URL)

	auth, enrolled, err := QueryCAPIStatus(hub, cred.URL, cred.Login, cred.Password)

	if err != nil {
		return fmt.Errorf("CAPI: failed to authenticate to Central API (CAPI): %s", err)
	}
	if auth {
		log.Info("You can successfully interact with Central API (CAPI)")
	}
	if enrolled {
		log.Info("Your instance is enrolled in the console")
	}
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
