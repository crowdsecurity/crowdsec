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

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
)

const CAPIURLPrefix = "v3"

func NewCapiCmd() *cobra.Command {
	var cmdCapi = &cobra.Command{
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

	cmdCapi.AddCommand(NewCapiRegisterCmd())
	cmdCapi.AddCommand(NewCapiStatusCmd())

	return cmdCapi
}


func runCapiRegister(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	outputFile, err := flags.GetString("file")
	if err != nil {
		return err
	}

	capiUserPrefix, err := flags.GetString("schmilblick")
	if err != nil {
		return err
	}

	capiURL, err := flags.GetString("capi-url")
	if err != nil {
		return err
	}

	capiUser, err := generateID(capiUserPrefix)
	if err != nil {
		return fmt.Errorf("unable to generate machine id: %s", err)
	}

	password := strfmt.Password(generatePassword(passwordLength))
	apiurl, err := url.Parse(capiURL)
	if err != nil {
		return fmt.Errorf("unable to parse api url %s: %s", capiURL, err)
	}
	_, err = apiclient.RegisterClient(&apiclient.Config{
		MachineID:     capiUser,
		Password:      password,
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiurl,
		VersionPrefix: CAPIURLPrefix,
	}, nil)

	if err != nil {
		return fmt.Errorf("api client register ('%s'): %s", capiURL, err)
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
		URL:      capiURL,
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to marshal api credentials: %s", err)
	}

	if dumpFile != "" {
		err = os.WriteFile(dumpFile, apiConfigDump, 0600)
		if err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %s", dumpFile, err)
		}
		log.Printf("Central API credentials dumped to '%s'", dumpFile)
	} else {
		fmt.Println(string(apiConfigDump))
	}

	log.Warning(ReloadMessage())
	return nil
}


func NewCapiRegisterCmd() *cobra.Command {
	var cmdCapiRegister = &cobra.Command{
		Use:               "register",
		Short:             "Register to Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE:              runCapiRegister,
	}

	flags := cmdCapiRegister.Flags()
	flags.StringP("file", "f", "", "output file destination")
	flags.String("schmilblick", "", "set a schmilblick (use in tests only)")
	flags.String("capi-url", "https://api.crowdsec.net/", "set the CAPI url")

	if err := flags.MarkHidden("schmilblick"); err != nil {
		log.Fatalf("failed to hide flag: %s", err)
	}

	return cmdCapiRegister
}


func runCapiStatus(cmd *cobra.Command, args []string) error {
	if err := require.CAPIRegistered(csConfig); err != nil {
		return err
	}

	password := strfmt.Password(csConfig.API.Server.OnlineClient.Credentials.Password)
	apiurl, err := url.Parse(csConfig.API.Server.OnlineClient.Credentials.URL)
	if err != nil {
		return fmt.Errorf("unable to parse api url %s: %s", csConfig.API.Server.OnlineClient.Credentials.URL, err)
	}

	if err := csConfig.LoadHub(); err != nil {
		return err
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		log.Info("Run 'sudo cscli hub update' to get the hub index")
		return fmt.Errorf("failed to load hub index : %s", err)
	}
	scenarios, err := cwhub.GetInstalledScenariosAsString()
	if err != nil {
		return fmt.Errorf("failed to get scenarios: %s", err)
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios installed, abort")
	}

	Client, err = apiclient.NewDefaultClient(apiurl, CAPIURLPrefix, fmt.Sprintf("crowdsec/%s", version.String()), nil)
	if err != nil {
		return fmt.Errorf("init default client: %s", err)
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
		return fmt.Errorf("failed to authenticate to Central API (CAPI): %s", err)
	}
	log.Infof("You can successfully interact with Central API (CAPI)")
	return nil
}


func NewCapiStatusCmd() *cobra.Command {
	var cmdCapiStatus = &cobra.Command{
		Use:               "status",
		Short:             "Check status with the Central API (CAPI)",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE:              runCapiStatus,
	}

	return cmdCapiStatus
}
