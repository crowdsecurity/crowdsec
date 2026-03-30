package clicapi

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/idgen"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var CAPIBaseURL = "https://api.crowdsec.net/"

type cliCapi struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliCapi {
	return &cliCapi{
		cfg: cfg,
	}
}

func (cli *cliCapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "capi [action]",
		Short:             "Manage interaction with Central API (CAPI)",
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
	}

	cmd.AddCommand(cli.newRegisterCmd())
	cmd.AddCommand(cli.newStatusCmd())

	return cmd
}

func (cli *cliCapi) register(ctx context.Context, capiUserPrefix string, outputFile string) error {
	cfg := cli.cfg()

	capiUser, err := idgen.GenerateMachineID(capiUserPrefix)
	if err != nil {
		return fmt.Errorf("unable to generate machine id: %w", err)
	}

	pstr, err := idgen.GeneratePassword(idgen.PasswordLength)
	if err != nil {
		return err
	}

	password := strfmt.Password(pstr)

	apiurl, err := url.Parse(CAPIBaseURL)
	if err != nil {
		return fmt.Errorf("unable to parse api url %s: %w", CAPIBaseURL, err)
	}

	_, err = apiclient.RegisterClient(ctx, &apiclient.Config{
		MachineID:     capiUser,
		Password:      password,
		URL:           apiurl,
		VersionPrefix: "v3",
	}, nil)
	if err != nil {
		return fmt.Errorf("api client register ('%s'): %w", CAPIBaseURL, err)
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
		URL:      CAPIBaseURL,
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to serialize api credentials: %w", err)
	}

	if dumpFile != "" {
		err = os.WriteFile(dumpFile, apiConfigDump, 0o600)
		if err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %w", dumpFile, err)
		}

		log.Infof("Central API credentials written to '%s'", dumpFile)
	} else {
		fmt.Fprintln(os.Stdout, string(apiConfigDump))
	}

	if msg := reload.UserMessage(); msg != "" {
		log.Warning(msg)
	}

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
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := require.LAPINoOnlineCreds(cfg); err != nil {
				return err
			}

			if err := require.CAPI(cfg); err != nil {
				return err
			}

			return cli.register(cmd.Context(), capiUserPrefix, outputFile)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "file", "f", "", "output file destination")
	cmd.Flags().StringVar(&capiUserPrefix, "schmilblick", "", "set a schmilblick (use in tests only)")

	_ = cmd.Flags().MarkHidden("schmilblick")

	return cmd
}

type capiStatus struct {
	authenticated    bool
	enrolled         bool
	subscriptionType string
}

// queryCAPIStatus checks if the Central API is reachable, and if the credentials are correct. It then checks if the instance is enrolled in the console.
func queryCAPIStatus(ctx context.Context, db *database.Client, hub *cwhub.Hub, credURL string, login string, password string) (capiStatus, error) {
	apiURL, err := url.Parse(credURL)
	if err != nil {
		return capiStatus{}, err
	}

	itemsForAPI := hub.GetInstalledListForAPI()

	passwd := strfmt.Password(password)

	client := apiclient.NewClient(&apiclient.Config{
		MachineID: login,
		Password:  passwd,
		URL:       apiURL,
		// I don't believe papi is needed to check enrollement
		// PapiURL:       papiURL,
		VersionPrefix: "v3",
		UpdateScenario: func(_ context.Context) ([]string, error) {
			return itemsForAPI, nil
		},
	})

	pw := strfmt.Password(password)

	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &pw,
		Scenarios: itemsForAPI,
	}

	authResp, _, err := client.Auth.AuthenticateWatcher(ctx, t)
	if err != nil {
		return capiStatus{}, err
	}

	if err := db.SaveAPICToken(ctx, authResp.Token); err != nil {
		return capiStatus{}, err
	}

	client.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token

	if client.IsEnrolled() {
		return capiStatus{true, true, client.GetSubscriptionType()}, nil
	}

	return capiStatus{true, false, ""}, nil
}

func (cli *cliCapi) Status(ctx context.Context, db *database.Client, out io.Writer, hub *cwhub.Hub) error {
	cfg := cli.cfg()

	if err := require.CAPIRegistered(cfg); err != nil {
		return err
	}

	cred := cfg.API.Server.OnlineClient.Credentials

	fmt.Fprintf(out, "Loaded credentials from %s\n", cfg.API.Server.OnlineClient.CredentialsFilePath)
	fmt.Fprintf(out, "Trying to authenticate with username %s on %s\n", cred.Login, cred.URL)

	status, err := queryCAPIStatus(ctx, db, hub, cred.URL, cred.Login, cred.Password)
	if err != nil {
		return fmt.Errorf("failed to authenticate to Central API (CAPI): %w", err)
	}

	if status.authenticated {
		fmt.Fprint(out, "You can successfully interact with Central API (CAPI)\n")
	}

	if status.enrolled {
		fmt.Fprint(out, "Your instance is enrolled in the console\n")
		fmt.Fprintf(out, "Subscription type: %s\n", status.subscriptionType)
	}

	switch *cfg.API.Server.OnlineClient.Sharing {
	case true:
		fmt.Fprint(out, "Sharing signals is enabled\n")
	case false:
		fmt.Fprint(out, "Sharing signals is disabled\n")
	}

	switch *cfg.API.Server.OnlineClient.PullConfig.Community {
	case true:
		fmt.Fprint(out, "Pulling community blocklist is enabled\n")
	case false:
		fmt.Fprint(out, "Pulling community blocklist is disabled\n")
	}

	switch *cfg.API.Server.OnlineClient.PullConfig.Blocklists {
	case true:
		fmt.Fprint(out, "Pulling blocklists from the console is enabled\n")
	case false:
		fmt.Fprint(out, "Pulling blocklists from the console is disabled\n")
	}

	return nil
}

func (cli *cliCapi) newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "status",
		Short:             "Check status with the Central API (CAPI)",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			ctx := cmd.Context()

			if err := require.LAPI(cfg); err != nil {
				return err
			}

			if err := require.CAPI(cfg); err != nil {
				return err
			}

			hub, err := require.Hub(cfg, nil)
			if err != nil {
				return err
			}

			db, err := require.DBClient(ctx, cfg.DbConfig)
			if err != nil {
				return err
			}

			return cli.Status(ctx, db, color.Output, hub)
		},
	}

	return cmd
}
