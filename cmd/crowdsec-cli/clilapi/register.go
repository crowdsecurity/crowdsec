package clilapi

import (
	"context"
	"fmt"
	"os"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/idgen"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

func (cli *cliLapi) register(ctx context.Context, apiURL string, outputFile string, machine string, token string) error {
	var err error

	lapiUser := machine
	cfg := cli.cfg()

	if lapiUser == "" {
		lapiUser, err = idgen.GenerateMachineID("")
		if err != nil {
			return fmt.Errorf("unable to generate machine id: %w", err)
		}
	}

	pstr, err := idgen.GeneratePassword(idgen.PasswordLength)
	if err != nil {
		return err
	}

	password := strfmt.Password(pstr)

	apiurl, err := prepareAPIURL(cfg.API.Client, apiURL)
	if err != nil {
		return fmt.Errorf("parsing api url: %w", err)
	}

	_, err = apiclient.RegisterClient(ctx, &apiclient.Config{
		MachineID:         lapiUser,
		Password:          password,
		RegistrationToken: token,
		URL:               apiurl,
		VersionPrefix:     LAPIURLPrefix,
	}, nil)
	if err != nil {
		return fmt.Errorf("api client register: %w", err)
	}

	log.Printf("Successfully registered to Local API (LAPI)")

	var dumpFile string

	if outputFile != "" {
		dumpFile = outputFile
	} else if cfg.API.Client.CredentialsFilePath != "" {
		dumpFile = cfg.API.Client.CredentialsFilePath
	} else {
		dumpFile = ""
	}

	apiCfg := cfg.API.Client.Credentials
	apiCfg.Login = lapiUser
	apiCfg.Password = password.String()

	if apiURL != "" {
		apiCfg.URL = apiURL
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to serialize api credentials: %w", err)
	}

	if dumpFile != "" {
		err = os.WriteFile(dumpFile, apiConfigDump, 0o600)
		if err != nil {
			return fmt.Errorf("write api credentials to '%s' failed: %w", dumpFile, err)
		}

		log.Printf("Local API credentials written to '%s'", dumpFile)
	} else {
		fmt.Printf("%s\n", string(apiConfigDump))
	}

	if msg := reload.UserMessage(); msg != "" {
		log.Warning(msg)
	}

	return nil
}

func (cli *cliLapi) newRegisterCmd() *cobra.Command {
	var (
		apiURL     string
		outputFile string
		machine    string
		token      string
	)

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a machine to Local API (LAPI)",
		Long: `Register your machine to the Local API (LAPI).
Keep in mind the machine needs to be validated by an administrator on LAPI side to be effective.`,
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.register(cmd.Context(), apiURL, outputFile, machine, token)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&apiURL, "url", "u", "", "URL of the API (ie. http://127.0.0.1)")
	flags.StringVarP(&outputFile, "file", "f", "", "output file destination")
	flags.StringVar(&machine, "machine", "", "Name of the machine to register with")
	flags.StringVar(&token, "token", "", "Auto registration token to use")

	return cmd
}
