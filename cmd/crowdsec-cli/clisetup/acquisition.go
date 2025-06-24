package clisetup

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

func (cli *cliSetup) newAcquisitionCmd() *cobra.Command {
	var toDir string

	cmd := &cobra.Command{
		Use:               "acquisition [setup_file] [flags]",
		Short:             "generate log acquisition configuration (datasources) from a setup file",
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := os.Open(args[0])
			if err != nil {
				return err
			}

			stup, err := setup.NewSetupFromYAML(input, true)
			if err != nil {
				return err
			}

			return cli.acquisition(stup.CollectAcquisitionSpecs(), toDir)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&toDir, "to-dir", "", "write the configuration to a directory, in multiple files")

	return cmd
}

func (cli *cliSetup) acquisition(acquisitionSpecs []setup.AcquisitionSpec, toDir string) error {
	output, err := setup.GenerateAcquisition(acquisitionSpecs, toDir)
	if err != nil {
		return err
	}

	if toDir == "" {
		fmt.Println(output)
	}

	return nil
}
