package climachine

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/idgen"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (cli *cliMachines) add(ctx context.Context, args []string, machinePassword string, dumpFile string, apiURL string, interactive bool, autoAdd bool, force bool) error {
	var (
		err       error
		machineID string
	)

	// create machineID if not specified by user
	if len(args) == 0 {
		if !autoAdd {
			return errors.New("please specify a machine name to add, or use --auto")
		}

		machineID, err = idgen.GenerateMachineID("")
		if err != nil {
			return fmt.Errorf("unable to generate machine id: %w", err)
		}
	} else {
		machineID = args[0]
	}

	clientCfg := cli.cfg().API.Client
	serverCfg := cli.cfg().API.Server

	/*check if file already exists*/
	if dumpFile == "" && clientCfg != nil && clientCfg.CredentialsFilePath != "" {
		credFile := clientCfg.CredentialsFilePath
		// use the default only if the file does not exist
		_, err = os.Stat(credFile)

		switch {
		case os.IsNotExist(err) || force:
			dumpFile = credFile
		case err != nil:
			return fmt.Errorf("unable to stat '%s': %w", credFile, err)
		default:
			return fmt.Errorf(`credentials file '%s' already exists: please remove it, use "--force" or specify a different file with "-f" ("-f -" for standard output)`, credFile)
		}
	}

	if dumpFile == "" {
		return errors.New(`please specify a file to dump credentials to, with -f ("-f -" for standard output)`)
	}

	// create a password if it's not specified by user
	if machinePassword == "" && !interactive {
		if !autoAdd {
			return errors.New("please specify a password with --password or use --auto")
		}

		machinePassword, err = idgen.GeneratePassword(idgen.PasswordLength)
		if err != nil {
			return err
		}
	} else if machinePassword == "" && interactive {
		qs := &survey.Password{
			Message: "Please provide a password for the machine:",
		}
		if err := survey.AskOne(qs, &machinePassword); err != nil {
			return err
		}
	}

	password := strfmt.Password(machinePassword)

	_, err = cli.db.CreateMachine(ctx, &machineID, &password, "", true, force, types.PasswordAuthType)
	if err != nil {
		return fmt.Errorf("unable to create machine: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Machine '%s' successfully added to the local API.\n", machineID)

	if apiURL == "" {
		if clientCfg != nil && clientCfg.Credentials != nil && clientCfg.Credentials.URL != "" {
			apiURL = clientCfg.Credentials.URL
		} else if serverCfg.ClientURL() != "" {
			apiURL = serverCfg.ClientURL()
		} else {
			return errors.New("unable to dump an api URL. Please provide it in your configuration or with the -u parameter")
		}
	}

	apiCfg := csconfig.ApiCredentialsCfg{
		Login:    machineID,
		Password: password.String(),
		URL:      apiURL,
	}

	apiConfigDump, err := yaml.Marshal(apiCfg)
	if err != nil {
		return fmt.Errorf("unable to serialize api credentials: %w", err)
	}

	if dumpFile != "" && dumpFile != "-" {
		if err = os.WriteFile(dumpFile, apiConfigDump, 0o600); err != nil {
			return fmt.Errorf("write api credentials in '%s' failed: %w", dumpFile, err)
		}

		fmt.Fprintf(os.Stderr, "API credentials written to '%s'.\n", dumpFile)
	} else {
		fmt.Print(string(apiConfigDump))
	}

	return nil
}

func (cli *cliMachines) newAddCmd() *cobra.Command {
	var (
		password    MachinePassword
		dumpFile    string
		apiURL      string
		interactive bool
		autoAdd     bool
		force       bool
	)

	cmd := &cobra.Command{
		Use:               "add",
		Short:             "add a single machine to the database",
		DisableAutoGenTag: true,
		Long:              `Register a new machine in the database. cscli should be on the same machine as LAPI.`,
		Example: `cscli machines add --auto
cscli machines add MyTestMachine --auto
cscli machines add MyTestMachine --password MyPassword
cscli machines add -f- --auto > /tmp/mycreds.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.add(cmd.Context(), args, string(password), dumpFile, apiURL, interactive, autoAdd, force)
		},
	}

	flags := cmd.Flags()
	flags.VarP(&password, "password", "p", "machine password to login to the API")
	flags.StringVarP(&dumpFile, "file", "f", "", "output file destination (defaults to "+csconfig.DefaultConfigPath("local_api_credentials.yaml")+")")
	flags.StringVarP(&apiURL, "url", "u", "", "URL of the local API")
	flags.BoolVarP(&interactive, "interactive", "i", false, "interactive mode to enter the password")
	flags.BoolVarP(&autoAdd, "auto", "a", false, "automatically generate password (and username if not provided)")
	flags.BoolVar(&force, "force", false, "will force add the machine if it already exists")

	return cmd
}
